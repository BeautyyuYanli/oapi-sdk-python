# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from lark_oapi.core.model import BaseResponse
from .list_agent_schedule_response_body import ListAgentScheduleResponseBody


class ListAgentScheduleResponse(BaseResponse):
    _types = {
        "data": ListAgentScheduleResponseBody
    }

    def __init__(self, d):
        super().__init__(d)
        self.data: Optional[ListAgentScheduleResponseBody] = None
        init(self, d, self._types)