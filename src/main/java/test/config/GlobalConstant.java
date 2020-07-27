package test.config;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 13:37 2020/7/24
 */
public class GlobalConstant {
    /**
     * 游客
     */
    String AUTH_ROLE_ANONYMOUS = "ANONYMOUS";

    /**
     * 普通用户
     */
    String AUTH_ROLE_USER = "USER";

    /**
     * 管理员
     */
    String AUTH_ROLE_ADMIN = "ADMIN";

    /**
     * 允许的请求头参数
     */
    static final String ACCESS_CONTROL_ALLOW_HEADERS = "X-Requested-With, Origin, Content-Type, Cookie,Authorization,Access-Token,system_type";

    /**
     * 允许的方法(  "*" 浏览器版本较低的时候不支持)
     */
    static final String ACCESS_CONTROL_ALLOW_METHODS = "GET,POST,DELETE,PUT,OPTIONS,HEAD,CONNECT,TRACE,PATCH,*";
}
