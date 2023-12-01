# Code generated by Lark OpenAPI.

from typing import Optional, List

from lark_oapi.core.construct import init
from .i18n_cls_name import I18nClsName


class Classification(object):
    _types = {
        "id": str,
        "name": str,
        "father_id": str,
        "i18n_names": List[I18nClsName],
    }

    def __init__(self, d=None):
        self.id: Optional[str] = None
        self.name: Optional[str] = None
        self.father_id: Optional[str] = None
        self.i18n_names: Optional[List[I18nClsName]] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "ClassificationBuilder":
        return ClassificationBuilder()


class ClassificationBuilder(object):
    def __init__(self) -> None:
        self._classification = Classification()

    def id(self, id: str) -> "ClassificationBuilder":
        self._classification.id = id
        return self

    def name(self, name: str) -> "ClassificationBuilder":
        self._classification.name = name
        return self

    def father_id(self, father_id: str) -> "ClassificationBuilder":
        self._classification.father_id = father_id
        return self

    def i18n_names(self, i18n_names: List[I18nClsName]) -> "ClassificationBuilder":
        self._classification.i18n_names = i18n_names
        return self

    def build(self) -> "Classification":
        return self._classification