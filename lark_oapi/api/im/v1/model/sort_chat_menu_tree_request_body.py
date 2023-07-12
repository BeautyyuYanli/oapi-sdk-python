# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init


class SortChatMenuTreeRequestBody(object):
    _types = {
        "chat_menu_top_level_ids": List[int],
    }

    def __init__(self, d):
        self.chat_menu_top_level_ids: Optional[List[int]] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "SortChatMenuTreeRequestBodyBuilder":
        return SortChatMenuTreeRequestBodyBuilder()


class SortChatMenuTreeRequestBodyBuilder(object):
    def __init__(self, sort_chat_menu_tree_request_body: SortChatMenuTreeRequestBody = SortChatMenuTreeRequestBody({})) -> None:
        self._sort_chat_menu_tree_request_body: SortChatMenuTreeRequestBody = sort_chat_menu_tree_request_body
    
    def chat_menu_top_level_ids(self, chat_menu_top_level_ids: List[int]) -> "SortChatMenuTreeRequestBodyBuilder":
        self._sort_chat_menu_tree_request_body.chat_menu_top_level_ids = chat_menu_top_level_ids
        return self
    
    def build(self) -> "SortChatMenuTreeRequestBody":
        return self._sort_chat_menu_tree_request_body