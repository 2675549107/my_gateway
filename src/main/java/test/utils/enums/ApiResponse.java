//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package test.utils.enums;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import test.config.ApiCode;
import test.config.ApiResult;

public enum ApiResponse {
    INSTANCE;

    private static final Logger log = LoggerFactory.getLogger(ApiResponse.class);
    public static final String SUCCESS_MESSAGE = "操作成功";
    public static final String SERVER_ERROR_DEFAULT_MESSAGE = "服务繁忙，请稍后";

    private ApiResponse() {
    }

    public <T> ApiResult<T> success(String message, T data) {
        return this.response(ApiCode.SUCCESS, message, data);
    }

    public <T> ApiResult<T> success(T data) {
        return this.success("操作成功", data);
    }

    public ApiResult success() {
        return this.success("操作成功", (Object)null);
    }

    public <T> ApiResult<T> error(ApiCode apiCode, String message, T data) {
        return this.response(apiCode, message, data);
    }

    public <T> ApiResult<T> error(HttpStatus status, String message, T data) {
        return this.response(status.value(), message, data);
    }

    public ApiResult error(ApiCode apiCode, String message) {
        return this.response(apiCode, message, (Object)null);
    }

    public ApiResult error(HttpStatus status, String message) {
        return this.response(status.value(), message, (Object)null);
    }

    private <T> ApiResult<T> response(ApiCode apiCode, String message, T data) {
        return ApiResult.create(apiCode.value(), message, data);
    }

    private <T> ApiResult<T> response(int code, String message, T data) {
        return ApiResult.create(code, message, data);
    }

    public <T> ApiResult<T> noResult(String message) {
        return (ApiResult<T>) this.response(ApiCode.NO_RESULT, message == null ? "无符合条件的信息" : message, (Object)null);
    }
}
