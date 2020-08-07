package test.config;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 16:06 2020/7/28
 */
public interface GlobalConstant {
    /**
     * token请求头的key
     */
    String HEADER_TOKEN_KEY = "Access-Token";

    /**
     * 游客身份
     */
    String AUTH_ROLE_ANONYMOUS = "ROLE_ANONYMOUS";

    /**
     * 用户身份 已登录
     */
    String AUTH_ROLE_USER = "ROLE_USER";

    /**
     * 用户身份 已登录
     */
    String AUTH_USER = "USER";

    /**
     * 用户身份 超级管理员
     */
    String AUTH_ROLE_ADMIN = "ROLE_ADMIN";

    /**
     * 身份 用于header中身份的传递
     */
    String ROLE_KEY = "Role";
}
