# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from .i18n import I18n
from .website_job_post_customized_value import WebsiteJobPostCustomizedValue


class WebsiteJobPostCustomizedData(object):
    _types = {
        "object_id": str,
        "name": I18n,
        "object_type": int,
        "value": WebsiteJobPostCustomizedValue,
    }

    def __init__(self, d):
        self.object_id: Optional[str] = None
        self.name: Optional[I18n] = None
        self.object_type: Optional[int] = None
        self.value: Optional[WebsiteJobPostCustomizedValue] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "WebsiteJobPostCustomizedDataBuilder":
        return WebsiteJobPostCustomizedDataBuilder()


class WebsiteJobPostCustomizedDataBuilder(object):
    def __init__(self, website_job_post_customized_data: WebsiteJobPostCustomizedData = WebsiteJobPostCustomizedData({})) -> None:
        self._website_job_post_customized_data: WebsiteJobPostCustomizedData = website_job_post_customized_data
    
    def object_id(self, object_id: str) -> "WebsiteJobPostCustomizedDataBuilder":
        self._website_job_post_customized_data.object_id = object_id
        return self
    
    def name(self, name: I18n) -> "WebsiteJobPostCustomizedDataBuilder":
        self._website_job_post_customized_data.name = name
        return self
    
    def object_type(self, object_type: int) -> "WebsiteJobPostCustomizedDataBuilder":
        self._website_job_post_customized_data.object_type = object_type
        return self
    
    def value(self, value: WebsiteJobPostCustomizedValue) -> "WebsiteJobPostCustomizedDataBuilder":
        self._website_job_post_customized_data.value = value
        return self
    
    def build(self) -> "WebsiteJobPostCustomizedData":
        return self._website_job_post_customized_data