# Code generated by Lark OpenAPI.

from typing import *

from lark_oapi.core.construct import init


class FilterSchema(object):
    _types = {
        "field": str,
        "type": str,
        "default_val": str,
        "field_type": str,
    }

    def __init__(self, d=None):
        self.field: Optional[str] = None
        self.type: Optional[str] = None
        self.default_val: Optional[str] = None
        self.field_type: Optional[str] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "FilterSchemaBuilder":
        return FilterSchemaBuilder()


class FilterSchemaBuilder(object):
    def __init__(self) -> None:
        self._filter_schema = FilterSchema()

    def field(self, field: str) -> "FilterSchemaBuilder":
        self._filter_schema.field = field
        return self

    def type(self, type: str) -> "FilterSchemaBuilder":
        self._filter_schema.type = type
        return self

    def default_val(self, default_val: str) -> "FilterSchemaBuilder":
        self._filter_schema.default_val = default_val
        return self

    def field_type(self, field_type: str) -> "FilterSchemaBuilder":
        self._filter_schema.field_type = field_type
        return self

    def build(self) -> "FilterSchema":
        return self._filter_schema
