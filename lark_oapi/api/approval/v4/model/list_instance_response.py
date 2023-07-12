# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from lark_oapi.core.model import BaseResponse
from .list_instance_response_body import ListInstanceResponseBody


class ListInstanceResponse(BaseResponse):
    _types = {
        "data": ListInstanceResponseBody
    }

    def __init__(self, d):
        super().__init__(d)
        self.data: Optional[ListInstanceResponseBody] = None
        init(self, d, self._types)