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
from lark_oapi.api.search.v2.model.create_data_source_item_request import CreateDataSourceItemRequest
from lark_oapi.api.search.v2.model.create_data_source_item_response import CreateDataSourceItemResponse
from lark_oapi.api.search.v2.model.delete_data_source_item_request import DeleteDataSourceItemRequest
from lark_oapi.api.search.v2.model.delete_data_source_item_response import DeleteDataSourceItemResponse
from lark_oapi.api.search.v2.model.get_data_source_item_request import GetDataSourceItemRequest
from lark_oapi.api.search.v2.model.get_data_source_item_response import GetDataSourceItemResponse


class DataSourceItem(object):
    def __init__(self, config: Config) -> None:
        self.config: Optional[Config] = config

    def create(self, request: CreateDataSourceItemRequest, option: RequestOption = RequestOption()) -> CreateDataSourceItemResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: CreateDataSourceItemResponse = JSON.unmarshal(str(resp.content, UTF_8), CreateDataSourceItemResponse)
        response.raw = resp

        return response

    def delete(self, request: DeleteDataSourceItemRequest, option: RequestOption = RequestOption()) -> DeleteDataSourceItemResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: DeleteDataSourceItemResponse = JSON.unmarshal(str(resp.content, UTF_8), DeleteDataSourceItemResponse)
        response.raw = resp

        return response

    def get(self, request: GetDataSourceItemRequest, option: RequestOption = RequestOption()) -> GetDataSourceItemResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: GetDataSourceItemResponse = JSON.unmarshal(str(resp.content, UTF_8), GetDataSourceItemResponse)
        response.raw = resp

        return response

    