# Code generated by Lark OpenAPI.

from typing import Optional

from lark_oapi.core.construct import init
from lark_oapi.core.model import BaseResponse
from .recognize_bank_card_response_body import RecognizeBankCardResponseBody


class RecognizeBankCardResponse(BaseResponse):
    _types = {
        "data": RecognizeBankCardResponseBody
    }

    def __init__(self, d=None):
        super().__init__(d)
        self.data: Optional[RecognizeBankCardResponseBody] = None
        init(self, d, self._types)