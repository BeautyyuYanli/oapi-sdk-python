# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from .request_doc import RequestDoc


class MetaRequest(object):
    _types = {
        "request_docs": List[RequestDoc],
        "with_url": bool,
    }

    def __init__(self, d):
        self.request_docs: Optional[List[RequestDoc]] = None
        self.with_url: Optional[bool] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "MetaRequestBuilder":
        return MetaRequestBuilder()


class MetaRequestBuilder(object):
    def __init__(self, meta_request: MetaRequest = MetaRequest({})) -> None:
        self._meta_request: MetaRequest = meta_request
    
    def request_docs(self, request_docs: List[RequestDoc]) -> "MetaRequestBuilder":
        self._meta_request.request_docs = request_docs
        return self
    
    def with_url(self, with_url: bool) -> "MetaRequestBuilder":
        self._meta_request.with_url = with_url
        return self
    
    def build(self) -> "MetaRequest":
        return self._meta_request