# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from lark_oapi.core.model import BaseResponse
from .patch_employee_type_response_body import PatchEmployeeTypeResponseBody


class PatchEmployeeTypeResponse(BaseResponse):
    _types = {
        "data": PatchEmployeeTypeResponseBody
    }

    def __init__(self, d):
        super().__init__(d)
        self.data: Optional[PatchEmployeeTypeResponseBody] = None
        init(self, d, self._types)