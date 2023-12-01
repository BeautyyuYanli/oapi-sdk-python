import os
import socket
from typing import Optional

from lark_oapi import Client
from lark_oapi.api.authen.v1 import (
    CreateOidcAccessTokenRequest,
    CreateOidcAccessTokenRequestBody,
    CreateOidcAccessTokenResponse,
    CreateOidcAccessTokenResponseBody,
)
from lark_oapi.api.authen.v1.resource import OidcAccessToken
from lark_oapi.core.model import Config
from lark_oapi.core.exception import ObtainAccessTokenException


def _http_once(
    host: str,
    port: int,
    buffer_size: int = 4096,
    timeout: Optional[float] = None,
    response: str = "OK",
) -> bytes:
    s = socket.create_server((host, port))
    s.settimeout(timeout)
    conn, _addr = s.accept()
    with conn:
        conn.settimeout(timeout)
        request = conn.recv(buffer_size)
        conn.sendall(response.encode("utf-8"))
    s.shutdown(socket.SHUT_RD)
    s.close()

    return request


def _get_user_token_with_click(config: Config) -> CreateOidcAccessTokenResponseBody:
    host = "localhost"
    port = 8080
    redirect_uri = f"http://{host}:{port}"
    url = f"{config.domain}/open-apis/authen/v1/authorize?app_id={config.app_id}&redirect_uri={redirect_uri}"
    print(url)
    try:
        req = _http_once(host=host, port=port, timeout=60 * 3)
    except Exception as e:
        raise ObtainAccessTokenException("user auth failed") from e
    first_line = req.split(b"\r\n")[0].decode()
    params_str = first_line.split(" ")[1].split("?")[1]
    params = {k: v for k, v in [item.split("=") for item in params_str.split("&")]}

    resp = OidcAccessToken(config).create(
        CreateOidcAccessTokenRequest.builder()
        .request_body(
            CreateOidcAccessTokenRequestBody.builder()
            .code(params["code"])
            .grant_type("authorization_code")
            .build()
        )
        .build()
    )
    if not resp.success():
        raise ObtainAccessTokenException(f"get user token failed: {resp.msg}")
    if resp.data is None:
        raise ObtainAccessTokenException("get user token failed: data is None")
    return resp.data


_client = (
    Client.builder()
    .app_id(os.environ["APP_ID"])
    .app_secret(os.environ["APP_SECRET"])
    .build()
)
token = _get_user_token_with_click(_client._config).access_token
print(token)
