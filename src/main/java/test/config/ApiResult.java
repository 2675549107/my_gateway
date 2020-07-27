package test.config;

import lombok.Data;

import java.io.Serializable;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 10:42 2020/6/19
 */
@Data
public final class ApiResult<T> implements Serializable {

    private static final long serialVersionUID = -14747713011039270L;
    /**
     * 状态码
     */
    private int code;

    /**
     * 消息
     */
    private String message;

    /**
     * 数据
     */
    private T data;

    public ApiResult() {
    }

    public ApiResult(int code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    /**
     * 创建接口响应
     *
     * @param code    状态码
     * @param message 消息
     * @param data    响应对象
     * @param <T>     响应对象类型
     * @return 响应数据
     */
    public static <T> ApiResult<T> create(int code, String message, T data) {
        return new ApiResult<>(code, message, data);
    }

    /**
     * 是否成功响应
     *
     * @return true/false
     */
    public boolean ok() {
        return this.code == ApiCode.SUCCESS.value();
    }

}
