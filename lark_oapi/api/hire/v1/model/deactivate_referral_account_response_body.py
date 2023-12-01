# Code generated by Lark OpenAPI.

from typing import Optional

from lark_oapi.core.construct import init
from .account import Account


class DeactivateReferralAccountResponseBody(object):
    _types = {
        "account": Account,
    }

    def __init__(self, d=None):
        self.account: Optional[Account] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "DeactivateReferralAccountResponseBodyBuilder":
        return DeactivateReferralAccountResponseBodyBuilder()


class DeactivateReferralAccountResponseBodyBuilder(object):
    def __init__(self) -> None:
        self._deactivate_referral_account_response_body = DeactivateReferralAccountResponseBody()

    def account(self, account: Account) -> "DeactivateReferralAccountResponseBodyBuilder":
        self._deactivate_referral_account_response_body.account = account
        return self

    def build(self) -> "DeactivateReferralAccountResponseBody":
        return self._deactivate_referral_account_response_body