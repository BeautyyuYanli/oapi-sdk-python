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
from lark_oapi.api.corehr.v1.model.create_national_id_type_request import CreateNationalIdTypeRequest
from lark_oapi.api.corehr.v1.model.create_national_id_type_response import CreateNationalIdTypeResponse
from lark_oapi.api.corehr.v1.model.delete_national_id_type_request import DeleteNationalIdTypeRequest
from lark_oapi.api.corehr.v1.model.delete_national_id_type_response import DeleteNationalIdTypeResponse
from lark_oapi.api.corehr.v1.model.get_national_id_type_request import GetNationalIdTypeRequest
from lark_oapi.api.corehr.v1.model.get_national_id_type_response import GetNationalIdTypeResponse
from lark_oapi.api.corehr.v1.model.list_national_id_type_request import ListNationalIdTypeRequest
from lark_oapi.api.corehr.v1.model.list_national_id_type_response import ListNationalIdTypeResponse
from lark_oapi.api.corehr.v1.model.patch_national_id_type_request import PatchNationalIdTypeRequest
from lark_oapi.api.corehr.v1.model.patch_national_id_type_response import PatchNationalIdTypeResponse


class NationalIdType(object):
    def __init__(self, config: Config) -> None:
        self.config: Optional[Config] = config

    def create(self, request: CreateNationalIdTypeRequest, option: RequestOption = RequestOption()) -> CreateNationalIdTypeResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: CreateNationalIdTypeResponse = JSON.unmarshal(str(resp.content, UTF_8), CreateNationalIdTypeResponse)
        response.raw = resp

        return response

    def delete(self, request: DeleteNationalIdTypeRequest, option: RequestOption = RequestOption()) -> DeleteNationalIdTypeResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: DeleteNationalIdTypeResponse = JSON.unmarshal(str(resp.content, UTF_8), DeleteNationalIdTypeResponse)
        response.raw = resp

        return response

    def get(self, request: GetNationalIdTypeRequest, option: RequestOption = RequestOption()) -> GetNationalIdTypeResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: GetNationalIdTypeResponse = JSON.unmarshal(str(resp.content, UTF_8), GetNationalIdTypeResponse)
        response.raw = resp

        return response

    def list(self, request: ListNationalIdTypeRequest, option: RequestOption = RequestOption()) -> ListNationalIdTypeResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: ListNationalIdTypeResponse = JSON.unmarshal(str(resp.content, UTF_8), ListNationalIdTypeResponse)
        response.raw = resp

        return response

    def patch(self, request: PatchNationalIdTypeRequest, option: RequestOption = RequestOption()) -> PatchNationalIdTypeResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: PatchNationalIdTypeResponse = JSON.unmarshal(str(resp.content, UTF_8), PatchNationalIdTypeResponse)
        response.raw = resp

        return response

    