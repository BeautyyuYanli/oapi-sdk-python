# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from lark_oapi.core.model import BaseResponse
from .get_public_mailbox_member_response_body import GetPublicMailboxMemberResponseBody


class GetPublicMailboxMemberResponse(BaseResponse):
    _types = {
        "data": GetPublicMailboxMemberResponseBody
    }

    def __init__(self, d):
        super().__init__(d)
        self.data: Optional[GetPublicMailboxMemberResponseBody] = None
        init(self, d, self._types)