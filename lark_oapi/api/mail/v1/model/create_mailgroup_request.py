# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.model import BaseRequest
from lark_oapi.core.enum import HttpMethod, AccessTokenType
from .mailgroup import Mailgroup


class CreateMailgroupRequest(BaseRequest):
    def __init__(self) -> None:
        super().__init__()
        self.request_body: Optional[Mailgroup] = None

    @staticmethod
    def builder() -> "CreateMailgroupRequestBuilder":
        return CreateMailgroupRequestBuilder()


class CreateMailgroupRequestBuilder(object):

    def __init__(self, create_mailgroup_request: CreateMailgroupRequest = CreateMailgroupRequest()) -> None:
        create_mailgroup_request.http_method = HttpMethod.POST
        create_mailgroup_request.uri = "/open-apis/mail/v1/mailgroups"
        create_mailgroup_request.token_types = {AccessTokenType.TENANT}
        self._create_mailgroup_request: CreateMailgroupRequest = create_mailgroup_request
    
    def request_body(self, request_body: Mailgroup) -> "CreateMailgroupRequestBuilder":
        self._create_mailgroup_request.request_body = request_body
        self._create_mailgroup_request.body = request_body
        return self

    def build(self) -> CreateMailgroupRequest:
        return self._create_mailgroup_request