package test.swagger;

import java.util.ArrayList;
import java.util.List;

/**
 * @author lieber
 * @create_date 2020/1/17 16:10
 */
public class SwaggerUrls {

    /**
     * swagger2默认的url后缀
     */
    public final static String SWAGGER2URL = "/v2/api-docs";

    private final static String SWAGGER2_RESOURCE = "/swagger-resources";

    private final static String SWAGGER2_WEBJAR = "/webjars";

    public final static List<String> URLS = new ArrayList<>(4);

    static {
        URLS.add(SWAGGER2URL);
        URLS.add(SWAGGER2_RESOURCE);
        URLS.add(SWAGGER2_WEBJAR);
    }

}
