package test.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import test.config.ApiResult;

import java.util.List;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 15:34 2020/7/29
 */
@FeignClient(value = "user-center-server", fallbackFactory = ResourceAuthApiClientFallbackFactory.class, path = "user-center-server")
public interface ResourceAuthApiClient {
    /**
     * 展示能访问该URL的所有角色
     * @param url
     *          需要访问的URL
     * @param method
     *          访问此URL的http请求方式
     * @return
     */
    @GetMapping("/user/load")
    ApiResult<List<String>> loadByUrl(@RequestParam("url")String url, @RequestParam("method")String method);
}
