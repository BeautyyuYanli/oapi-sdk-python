# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.model import BaseRequest
from lark_oapi.core.enum import HttpMethod, AccessTokenType
from .query_user_flow_request_body import QueryUserFlowRequestBody


class QueryUserFlowRequest(BaseRequest):
    def __init__(self) -> None:
        super().__init__()
        self.employee_type: Optional[str] = None
        self.include_terminated_user: Optional[bool] = None
        self.request_body: Optional[QueryUserFlowRequestBody] = None

    @staticmethod
    def builder() -> "QueryUserFlowRequestBuilder":
        return QueryUserFlowRequestBuilder()


class QueryUserFlowRequestBuilder(object):

    def __init__(self, query_user_flow_request: QueryUserFlowRequest = QueryUserFlowRequest()) -> None:
        query_user_flow_request.http_method = HttpMethod.POST
        query_user_flow_request.uri = "/open-apis/attendance/v1/user_flows/query"
        query_user_flow_request.token_types = {AccessTokenType.TENANT}
        self._query_user_flow_request: QueryUserFlowRequest = query_user_flow_request
    
    def employee_type(self, employee_type: str) -> "QueryUserFlowRequestBuilder":
        self._query_user_flow_request.employee_type = employee_type
        self._query_user_flow_request.queries["employee_type"] = str(employee_type)
        return self
    
    def include_terminated_user(self, include_terminated_user: bool) -> "QueryUserFlowRequestBuilder":
        self._query_user_flow_request.include_terminated_user = include_terminated_user
        self._query_user_flow_request.queries["include_terminated_user"] = str(include_terminated_user)
        return self
    
    def request_body(self, request_body: QueryUserFlowRequestBody) -> "QueryUserFlowRequestBuilder":
        self._query_user_flow_request.request_body = request_body
        self._query_user_flow_request.body = request_body
        return self

    def build(self) -> QueryUserFlowRequest:
        return self._query_user_flow_request