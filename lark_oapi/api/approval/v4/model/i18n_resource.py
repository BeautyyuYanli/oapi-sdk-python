# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init
from .i18n_resource_text import I18nResourceText


class I18nResource(object):
    _types = {
        "locale": str,
        "texts": List[I18nResourceText],
        "is_default": bool,
    }

    def __init__(self, d):
        self.locale: Optional[str] = None
        self.texts: Optional[List[I18nResourceText]] = None
        self.is_default: Optional[bool] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "I18nResourceBuilder":
        return I18nResourceBuilder()


class I18nResourceBuilder(object):
    def __init__(self, i18n_resource: I18nResource = I18nResource({})) -> None:
        self._i18n_resource: I18nResource = i18n_resource
    
    def locale(self, locale: str) -> "I18nResourceBuilder":
        self._i18n_resource.locale = locale
        return self
    
    def texts(self, texts: List[I18nResourceText]) -> "I18nResourceBuilder":
        self._i18n_resource.texts = texts
        return self
    
    def is_default(self, is_default: bool) -> "I18nResourceBuilder":
        self._i18n_resource.is_default = is_default
        return self
    
    def build(self) -> "I18nResource":
        return self._i18n_resource