# Code generated by Lark OpenAPI.

import lark_oapi as lark
from lark_oapi.api.vc.v1 import *


def main():
    # 创建client
    client = lark.Client.builder() \
        .app_id(lark.APP_ID) \
        .app_secret(lark.APP_SECRET) \
        .log_level(lark.LogLevel.DEBUG) \
        .build()

    # 构造请求对象
    request: MeetingListExportRequest = MeetingListExportRequest.builder() \
        .user_id_type("user_id") \
        .request_body(MeetingListExportRequestBody.builder()
                      .start_time("1655276858")
                      .end_time("1655276858")
                      .meeting_no("123456789")
                      .user_id("ou_3ec3f6a28a0d08c45d895276e8e5e19b")
                      .room_id("omm_eada1d61a550955240c28757e7dec3af")
                      .build()) \
        .build()

    # 发起请求
    response: MeetingListExportResponse = client.vc.v1.export.meeting_list(request)

    # 处理失败返回
    if not response.success():
        lark.logger.error(
            f"client.vc.v1.export.meeting_list failed, code: {response.code}, msg: {response.msg}, log_id: {response.get_log_id()}")
        return

    # 处理业务结果
    lark.logger.info(lark.JSON.marshal(response.data, indent=4))


if __name__ == "__main__":
    main()
