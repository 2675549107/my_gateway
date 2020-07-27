package test.config;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 10:43 2020/6/19
 */
public enum ApiCode {

    /**
     * 请求成功
     */
    SUCCESS(200),

    /**
     * 参数错误
     */
    PARAM_ERROR(400),

    /**
     * 客户端认证失败
     */
    AUTHENTICATE_ERROR(401),

    /**
     * 权限错误
     */
    JURISDICTION_ERROR(403),

    /**
     * 没有找到资源
     */
    NOT_FIND(404),

    /**
     * 被其他表使用,不能删除
     */
    IS_USED(405),

    /**
     * 服务器错误
     */
    SERVER_ERROR(500),

    /**
     * 数据正在操作中
     */
    IN_PROGRESS(501),

    // ...... 自定义错误码

    /**
     * 无符合条件的结果
     */
    NO_RESULT(200404),

    /**
     * 价格更改
     */
    PRICE_CHANGE(500001),

    /**
     * CODE过期
     */
    CODE_EXPIRE(400001);

    private int value;

    ApiCode(int value) {
        this.value = value;
    }

    public int value() {
        return value;
    }
}
