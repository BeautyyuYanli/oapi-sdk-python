# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from .version import Version


class ListFileVersionResponseBody(object):
    _types = {
        "items": List[Version],
        "page_token": str,
        "has_more": bool,
    }

    def __init__(self, d):
        self.items: Optional[List[Version]] = None
        self.page_token: Optional[str] = None
        self.has_more: Optional[bool] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "ListFileVersionResponseBodyBuilder":
        return ListFileVersionResponseBodyBuilder()


class ListFileVersionResponseBodyBuilder(object):
    def __init__(self, list_file_version_response_body: ListFileVersionResponseBody = ListFileVersionResponseBody({})) -> None:
        self._list_file_version_response_body: ListFileVersionResponseBody = list_file_version_response_body
    
    def items(self, items: List[Version]) -> "ListFileVersionResponseBodyBuilder":
        self._list_file_version_response_body.items = items
        return self
    
    def page_token(self, page_token: str) -> "ListFileVersionResponseBodyBuilder":
        self._list_file_version_response_body.page_token = page_token
        return self
    
    def has_more(self, has_more: bool) -> "ListFileVersionResponseBodyBuilder":
        self._list_file_version_response_body.has_more = has_more
        return self
    
    def build(self) -> "ListFileVersionResponseBody":
        return self._list_file_version_response_body