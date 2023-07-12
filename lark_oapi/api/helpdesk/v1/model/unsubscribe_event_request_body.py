# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from .event import Event


class UnsubscribeEventRequestBody(object):
    _types = {
        "events": List[Event],
    }

    def __init__(self, d):
        self.events: Optional[List[Event]] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "UnsubscribeEventRequestBodyBuilder":
        return UnsubscribeEventRequestBodyBuilder()


class UnsubscribeEventRequestBodyBuilder(object):
    def __init__(self, unsubscribe_event_request_body: UnsubscribeEventRequestBody = UnsubscribeEventRequestBody({})) -> None:
        self._unsubscribe_event_request_body: UnsubscribeEventRequestBody = unsubscribe_event_request_body
    
    def events(self, events: List[Event]) -> "UnsubscribeEventRequestBodyBuilder":
        self._unsubscribe_event_request_body.events = events
        return self
    
    def build(self) -> "UnsubscribeEventRequestBody":
        return self._unsubscribe_event_request_body