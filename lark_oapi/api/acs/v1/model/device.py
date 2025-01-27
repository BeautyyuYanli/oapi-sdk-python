# Code generated by Lark OpenAPI.

from typing import Optional

from lark_oapi.core.construct import init


class Device(object):
    _types = {
        "device_id": int,
        "device_name": str,
        "device_sn": str,
    }

    def __init__(self, d=None):
        self.device_id: Optional[int] = None
        self.device_name: Optional[str] = None
        self.device_sn: Optional[str] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "DeviceBuilder":
        return DeviceBuilder()


class DeviceBuilder(object):
    def __init__(self) -> None:
        self._device = Device()

    def device_id(self, device_id: int) -> "DeviceBuilder":
        self._device.device_id = device_id
        return self

    def device_name(self, device_name: str) -> "DeviceBuilder":
        self._device.device_name = device_name
        return self

    def device_sn(self, device_sn: str) -> "DeviceBuilder":
        self._device.device_sn = device_sn
        return self

    def build(self) -> "Device":
        return self._device
