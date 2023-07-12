# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init


class Identity(object):
    _types = {
        "identity_name": str,
        "identity_code": str,
        "mobile": str,
    }

    def __init__(self, d):
        self.identity_name: Optional[str] = None
        self.identity_code: Optional[str] = None
        self.mobile: Optional[str] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "IdentityBuilder":
        return IdentityBuilder()


class IdentityBuilder(object):
    def __init__(self, identity: Identity = Identity({})) -> None:
        self._identity: Identity = identity
    
    def identity_name(self, identity_name: str) -> "IdentityBuilder":
        self._identity.identity_name = identity_name
        return self
    
    def identity_code(self, identity_code: str) -> "IdentityBuilder":
        self._identity.identity_code = identity_code
        return self
    
    def mobile(self, mobile: str) -> "IdentityBuilder":
        self._identity.mobile = mobile
        return self
    
    def build(self) -> "Identity":
        return self._identity