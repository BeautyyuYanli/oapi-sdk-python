# Code generated by Lark OpenAPI.

from typing import Optional

from lark_oapi.core.enum import HttpMethod, AccessTokenType
from lark_oapi.core.model import BaseRequest
from .add_custom_field_request_body import AddCustomFieldRequestBody


class AddCustomFieldRequest(BaseRequest):
    def __init__(self) -> None:
        super().__init__()
        self.custom_field_guid: Optional[str] = None
        self.request_body: Optional[AddCustomFieldRequestBody] = None

    @staticmethod
    def builder() -> "AddCustomFieldRequestBuilder":
        return AddCustomFieldRequestBuilder()


class AddCustomFieldRequestBuilder(object):

    def __init__(self) -> None:
        add_custom_field_request = AddCustomFieldRequest()
        add_custom_field_request.http_method = HttpMethod.POST
        add_custom_field_request.uri = "/open-apis/task/v2/custom_fields/:custom_field_guid/add"
        add_custom_field_request.token_types = {AccessTokenType.TENANT, AccessTokenType.USER}
        self._add_custom_field_request: AddCustomFieldRequest = add_custom_field_request

    def custom_field_guid(self, custom_field_guid: str) -> "AddCustomFieldRequestBuilder":
        self._add_custom_field_request.custom_field_guid = custom_field_guid
        self._add_custom_field_request.paths["custom_field_guid"] = str(custom_field_guid)
        return self

    def request_body(self, request_body: AddCustomFieldRequestBody) -> "AddCustomFieldRequestBuilder":
        self._add_custom_field_request.request_body = request_body
        self._add_custom_field_request.body = request_body
        return self

    def build(self) -> AddCustomFieldRequest:
        return self._add_custom_field_request