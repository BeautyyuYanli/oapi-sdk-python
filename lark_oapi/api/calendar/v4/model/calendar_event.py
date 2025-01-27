# Code generated by Lark OpenAPI.

from typing import Optional, List

from lark_oapi.core.construct import init
from .event_location import EventLocation
from .reminder import Reminder
from .schema import Schema
from .time_info import TimeInfo
from .vchat import Vchat


class CalendarEvent(object):
    _types = {
        "event_id": str,
        "organizer_calendar_id": str,
        "summary": str,
        "description": str,
        "need_notification": bool,
        "start_time": TimeInfo,
        "end_time": TimeInfo,
        "vchat": Vchat,
        "visibility": str,
        "attendee_ability": str,
        "free_busy_status": str,
        "location": EventLocation,
        "color": int,
        "reminders": List[Reminder],
        "recurrence": str,
        "status": str,
        "is_exception": bool,
        "recurring_event_id": str,
        "create_time": str,
        "schemas": List[Schema],
    }

    def __init__(self, d=None):
        self.event_id: Optional[str] = None
        self.organizer_calendar_id: Optional[str] = None
        self.summary: Optional[str] = None
        self.description: Optional[str] = None
        self.need_notification: Optional[bool] = None
        self.start_time: Optional[TimeInfo] = None
        self.end_time: Optional[TimeInfo] = None
        self.vchat: Optional[Vchat] = None
        self.visibility: Optional[str] = None
        self.attendee_ability: Optional[str] = None
        self.free_busy_status: Optional[str] = None
        self.location: Optional[EventLocation] = None
        self.color: Optional[int] = None
        self.reminders: Optional[List[Reminder]] = None
        self.recurrence: Optional[str] = None
        self.status: Optional[str] = None
        self.is_exception: Optional[bool] = None
        self.recurring_event_id: Optional[str] = None
        self.create_time: Optional[str] = None
        self.schemas: Optional[List[Schema]] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "CalendarEventBuilder":
        return CalendarEventBuilder()


class CalendarEventBuilder(object):
    def __init__(self) -> None:
        self._calendar_event = CalendarEvent()

    def event_id(self, event_id: str) -> "CalendarEventBuilder":
        self._calendar_event.event_id = event_id
        return self

    def organizer_calendar_id(self, organizer_calendar_id: str) -> "CalendarEventBuilder":
        self._calendar_event.organizer_calendar_id = organizer_calendar_id
        return self

    def summary(self, summary: str) -> "CalendarEventBuilder":
        self._calendar_event.summary = summary
        return self

    def description(self, description: str) -> "CalendarEventBuilder":
        self._calendar_event.description = description
        return self

    def need_notification(self, need_notification: bool) -> "CalendarEventBuilder":
        self._calendar_event.need_notification = need_notification
        return self

    def start_time(self, start_time: TimeInfo) -> "CalendarEventBuilder":
        self._calendar_event.start_time = start_time
        return self

    def end_time(self, end_time: TimeInfo) -> "CalendarEventBuilder":
        self._calendar_event.end_time = end_time
        return self

    def vchat(self, vchat: Vchat) -> "CalendarEventBuilder":
        self._calendar_event.vchat = vchat
        return self

    def visibility(self, visibility: str) -> "CalendarEventBuilder":
        self._calendar_event.visibility = visibility
        return self

    def attendee_ability(self, attendee_ability: str) -> "CalendarEventBuilder":
        self._calendar_event.attendee_ability = attendee_ability
        return self

    def free_busy_status(self, free_busy_status: str) -> "CalendarEventBuilder":
        self._calendar_event.free_busy_status = free_busy_status
        return self

    def location(self, location: EventLocation) -> "CalendarEventBuilder":
        self._calendar_event.location = location
        return self

    def color(self, color: int) -> "CalendarEventBuilder":
        self._calendar_event.color = color
        return self

    def reminders(self, reminders: List[Reminder]) -> "CalendarEventBuilder":
        self._calendar_event.reminders = reminders
        return self

    def recurrence(self, recurrence: str) -> "CalendarEventBuilder":
        self._calendar_event.recurrence = recurrence
        return self

    def status(self, status: str) -> "CalendarEventBuilder":
        self._calendar_event.status = status
        return self

    def is_exception(self, is_exception: bool) -> "CalendarEventBuilder":
        self._calendar_event.is_exception = is_exception
        return self

    def recurring_event_id(self, recurring_event_id: str) -> "CalendarEventBuilder":
        self._calendar_event.recurring_event_id = recurring_event_id
        return self

    def create_time(self, create_time: str) -> "CalendarEventBuilder":
        self._calendar_event.create_time = create_time
        return self

    def schemas(self, schemas: List[Schema]) -> "CalendarEventBuilder":
        self._calendar_event.schemas = schemas
        return self

    def build(self) -> "CalendarEvent":
        return self._calendar_event
