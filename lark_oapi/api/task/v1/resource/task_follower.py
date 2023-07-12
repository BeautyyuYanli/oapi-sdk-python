# Code generated by Lark OpenAPI.

import io
from typing import *
from typing import IO
from lark_oapi.core.const import UTF_8, CONTENT_TYPE
from lark_oapi.core import JSON
from lark_oapi.core.token import verify
from lark_oapi.core.http import Transport
from lark_oapi.core.model import Config, RequestOption, RawResponse
from lark_oapi.core.utils import Files
from requests_toolbelt import MultipartEncoder
from lark_oapi.api.task.v1.model.create_task_follower_request import CreateTaskFollowerRequest
from lark_oapi.api.task.v1.model.create_task_follower_response import CreateTaskFollowerResponse
from lark_oapi.api.task.v1.model.delete_task_follower_request import DeleteTaskFollowerRequest
from lark_oapi.api.task.v1.model.delete_task_follower_response import DeleteTaskFollowerResponse
from lark_oapi.api.task.v1.model.list_task_follower_request import ListTaskFollowerRequest
from lark_oapi.api.task.v1.model.list_task_follower_response import ListTaskFollowerResponse


class TaskFollower(object):
    def __init__(self, config: Config) -> None:
        self.config: Optional[Config] = config

    def create(self, request: CreateTaskFollowerRequest, option: RequestOption = RequestOption()) -> CreateTaskFollowerResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: CreateTaskFollowerResponse = JSON.unmarshal(str(resp.content, UTF_8), CreateTaskFollowerResponse)
        response.raw = resp

        return response

    def delete(self, request: DeleteTaskFollowerRequest, option: RequestOption = RequestOption()) -> DeleteTaskFollowerResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: DeleteTaskFollowerResponse = JSON.unmarshal(str(resp.content, UTF_8), DeleteTaskFollowerResponse)
        response.raw = resp

        return response

    def list(self, request: ListTaskFollowerRequest, option: RequestOption = RequestOption()) -> ListTaskFollowerResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: ListTaskFollowerResponse = JSON.unmarshal(str(resp.content, UTF_8), ListTaskFollowerResponse)
        response.raw = resp

        return response

    