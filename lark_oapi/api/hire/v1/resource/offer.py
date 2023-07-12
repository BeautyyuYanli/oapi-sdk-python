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
from lark_oapi.api.hire.v1.model.create_offer_request import CreateOfferRequest
from lark_oapi.api.hire.v1.model.create_offer_response import CreateOfferResponse
from lark_oapi.api.hire.v1.model.get_offer_request import GetOfferRequest
from lark_oapi.api.hire.v1.model.get_offer_response import GetOfferResponse
from lark_oapi.api.hire.v1.model.intern_offer_status_offer_request import InternOfferStatusOfferRequest
from lark_oapi.api.hire.v1.model.intern_offer_status_offer_response import InternOfferStatusOfferResponse
from lark_oapi.api.hire.v1.model.list_offer_request import ListOfferRequest
from lark_oapi.api.hire.v1.model.list_offer_response import ListOfferResponse
from lark_oapi.api.hire.v1.model.offer_status_offer_request import OfferStatusOfferRequest
from lark_oapi.api.hire.v1.model.offer_status_offer_response import OfferStatusOfferResponse
from lark_oapi.api.hire.v1.model.update_offer_request import UpdateOfferRequest
from lark_oapi.api.hire.v1.model.update_offer_response import UpdateOfferResponse


class Offer(object):
    def __init__(self, config: Config) -> None:
        self.config: Optional[Config] = config

    def create(self, request: CreateOfferRequest, option: RequestOption = RequestOption()) -> CreateOfferResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: CreateOfferResponse = JSON.unmarshal(str(resp.content, UTF_8), CreateOfferResponse)
        response.raw = resp

        return response

    def get(self, request: GetOfferRequest, option: RequestOption = RequestOption()) -> GetOfferResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: GetOfferResponse = JSON.unmarshal(str(resp.content, UTF_8), GetOfferResponse)
        response.raw = resp

        return response

    def intern_offer_status(self, request: InternOfferStatusOfferRequest, option: RequestOption = RequestOption()) -> InternOfferStatusOfferResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: InternOfferStatusOfferResponse = JSON.unmarshal(str(resp.content, UTF_8), InternOfferStatusOfferResponse)
        response.raw = resp

        return response

    def list(self, request: ListOfferRequest, option: RequestOption = RequestOption()) -> ListOfferResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: ListOfferResponse = JSON.unmarshal(str(resp.content, UTF_8), ListOfferResponse)
        response.raw = resp

        return response

    def offer_status(self, request: OfferStatusOfferRequest, option: RequestOption = RequestOption()) -> OfferStatusOfferResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: OfferStatusOfferResponse = JSON.unmarshal(str(resp.content, UTF_8), OfferStatusOfferResponse)
        response.raw = resp

        return response

    def update(self, request: UpdateOfferRequest, option: RequestOption = RequestOption()) -> UpdateOfferResponse:
        # 鉴权、获取token
        verify(self.config, request, option)
        
        # 发起请求
        resp: RawResponse = Transport.execute(self.config, request, option)
        
        # 反序列化
        response: UpdateOfferResponse = JSON.unmarshal(str(resp.content, UTF_8), UpdateOfferResponse)
        response.raw = resp

        return response

    