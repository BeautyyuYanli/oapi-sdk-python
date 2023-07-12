# Code generated by Lark OpenAPI.

from typing import *
from typing import IO
from lark_oapi.core.construct import init


class ExportTask(object):
    _types = {
        "file_extension": str,
        "token": str,
        "type": str,
        "file_name": str,
        "sub_id": str,
        "file_token": str,
        "file_size": int,
        "job_error_msg": str,
        "job_status": int,
    }

    def __init__(self, d):
        self.file_extension: Optional[str] = None
        self.token: Optional[str] = None
        self.type: Optional[str] = None
        self.file_name: Optional[str] = None
        self.sub_id: Optional[str] = None
        self.file_token: Optional[str] = None
        self.file_size: Optional[int] = None
        self.job_error_msg: Optional[str] = None
        self.job_status: Optional[int] = None
        init(self, d, self._types)

    @staticmethod
    def builder() -> "ExportTaskBuilder":
        return ExportTaskBuilder()


class ExportTaskBuilder(object):
    def __init__(self, export_task: ExportTask = ExportTask({})) -> None:
        self._export_task: ExportTask = export_task
    
    def file_extension(self, file_extension: str) -> "ExportTaskBuilder":
        self._export_task.file_extension = file_extension
        return self
    
    def token(self, token: str) -> "ExportTaskBuilder":
        self._export_task.token = token
        return self
    
    def type(self, type: str) -> "ExportTaskBuilder":
        self._export_task.type = type
        return self
    
    def file_name(self, file_name: str) -> "ExportTaskBuilder":
        self._export_task.file_name = file_name
        return self
    
    def sub_id(self, sub_id: str) -> "ExportTaskBuilder":
        self._export_task.sub_id = sub_id
        return self
    
    def file_token(self, file_token: str) -> "ExportTaskBuilder":
        self._export_task.file_token = file_token
        return self
    
    def file_size(self, file_size: int) -> "ExportTaskBuilder":
        self._export_task.file_size = file_size
        return self
    
    def job_error_msg(self, job_error_msg: str) -> "ExportTaskBuilder":
        self._export_task.job_error_msg = job_error_msg
        return self
    
    def job_status(self, job_status: int) -> "ExportTaskBuilder":
        self._export_task.job_status = job_status
        return self
    
    def build(self) -> "ExportTask":
        return self._export_task