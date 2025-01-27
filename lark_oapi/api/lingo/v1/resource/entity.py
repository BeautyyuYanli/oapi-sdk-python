# Code generated by Lark OpenAPI.

from typing import Optional

from lark_oapi.core import JSON
from lark_oapi.core.const import UTF_8, CONTENT_TYPE, APPLICATION_JSON
from lark_oapi.core.http import Transport
from lark_oapi.core.model import Config, RequestOption, RawResponse
from lark_oapi.core.token import verify
from ..model.create_entity_request import CreateEntityRequest
from ..model.create_entity_response import CreateEntityResponse
from ..model.get_entity_request import GetEntityRequest
from ..model.get_entity_response import GetEntityResponse
from ..model.highlight_entity_request import HighlightEntityRequest
from ..model.highlight_entity_response import HighlightEntityResponse
from ..model.list_entity_request import ListEntityRequest
from ..model.list_entity_response import ListEntityResponse
from ..model.match_entity_request import MatchEntityRequest
from ..model.match_entity_response import MatchEntityResponse
from ..model.search_entity_request import SearchEntityRequest
from ..model.search_entity_response import SearchEntityResponse
from ..model.update_entity_request import UpdateEntityRequest
from ..model.update_entity_response import UpdateEntityResponse


class Entity(object):
    def __init__(self, config: Config) -> None:
        self.config: Config = config

    def create(self, request: CreateEntityRequest, option: Optional[RequestOption] = None) -> CreateEntityResponse:
        if option is None:
            option = RequestOption()

        # 鉴权、获取 token
        verify(self.config, request, option)

        # 添加 content-type
        if request.body is not None:
            option.headers[CONTENT_TYPE] = f"{APPLICATION_JSON}; charset=utf-8"

        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)

        # 反序列化
        response: CreateEntityResponse = JSON.unmarshal(str(resp.content, UTF_8), CreateEntityResponse)
        response.raw = resp

        return response

    def get(self, request: GetEntityRequest, option: Optional[RequestOption] = None) -> GetEntityResponse:
        if option is None:
            option = RequestOption()

        # 鉴权、获取 token
        verify(self.config, request, option)

        # 添加 content-type
        if request.body is not None:
            option.headers[CONTENT_TYPE] = f"{APPLICATION_JSON}; charset=utf-8"

        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)

        # 反序列化
        response: GetEntityResponse = JSON.unmarshal(str(resp.content, UTF_8), GetEntityResponse)
        response.raw = resp

        return response

    def highlight(self, request: HighlightEntityRequest,
                  option: Optional[RequestOption] = None) -> HighlightEntityResponse:
        if option is None:
            option = RequestOption()

        # 鉴权、获取 token
        verify(self.config, request, option)

        # 添加 content-type
        if request.body is not None:
            option.headers[CONTENT_TYPE] = f"{APPLICATION_JSON}; charset=utf-8"

        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)

        # 反序列化
        response: HighlightEntityResponse = JSON.unmarshal(str(resp.content, UTF_8), HighlightEntityResponse)
        response.raw = resp

        return response

    def list(self, request: ListEntityRequest, option: Optional[RequestOption] = None) -> ListEntityResponse:
        if option is None:
            option = RequestOption()

        # 鉴权、获取 token
        verify(self.config, request, option)

        # 添加 content-type
        if request.body is not None:
            option.headers[CONTENT_TYPE] = f"{APPLICATION_JSON}; charset=utf-8"

        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)

        # 反序列化
        response: ListEntityResponse = JSON.unmarshal(str(resp.content, UTF_8), ListEntityResponse)
        response.raw = resp

        return response

    def match(self, request: MatchEntityRequest, option: Optional[RequestOption] = None) -> MatchEntityResponse:
        if option is None:
            option = RequestOption()

        # 鉴权、获取 token
        verify(self.config, request, option)

        # 添加 content-type
        if request.body is not None:
            option.headers[CONTENT_TYPE] = f"{APPLICATION_JSON}; charset=utf-8"

        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)

        # 反序列化
        response: MatchEntityResponse = JSON.unmarshal(str(resp.content, UTF_8), MatchEntityResponse)
        response.raw = resp

        return response

    def search(self, request: SearchEntityRequest, option: Optional[RequestOption] = None) -> SearchEntityResponse:
        if option is None:
            option = RequestOption()

        # 鉴权、获取 token
        verify(self.config, request, option)

        # 添加 content-type
        if request.body is not None:
            option.headers[CONTENT_TYPE] = f"{APPLICATION_JSON}; charset=utf-8"

        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)

        # 反序列化
        response: SearchEntityResponse = JSON.unmarshal(str(resp.content, UTF_8), SearchEntityResponse)
        response.raw = resp

        return response

    def update(self, request: UpdateEntityRequest, option: Optional[RequestOption] = None) -> UpdateEntityResponse:
        if option is None:
            option = RequestOption()

        # 鉴权、获取 token
        verify(self.config, request, option)

        # 添加 content-type
        if request.body is not None:
            option.headers[CONTENT_TYPE] = f"{APPLICATION_JSON}; charset=utf-8"

        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)

        # 反序列化
        response: UpdateEntityResponse = JSON.unmarshal(str(resp.content, UTF_8), UpdateEntityResponse)
        response.raw = resp

        return response
