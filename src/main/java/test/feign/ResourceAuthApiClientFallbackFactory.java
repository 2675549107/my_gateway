package test.feign;

import feign.hystrix.FallbackFactory;
import lombok.extern.slf4j.Slf4j;
import net.iotcd.api.sdk.core.result.ApiCode;
import net.iotcd.api.sdk.core.result.ApiResponse;
import net.iotcd.api.sdk.core.result.ApiResult;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 15:34 2020/7/29
 */
@Component
@Slf4j
public class ResourceAuthApiClientFallbackFactory implements FallbackFactory<ResourceAuthApiClient> {
    @Override
    public ResourceAuthApiClient create(Throwable cause) {
        cause.printStackTrace();
        //不要用lambda表达式，因为如果接口有多个方法就不能写成lambda表达式了，就要改代码
        return new ResourceAuthApiClient() {
            @Override
            public ApiResult<List<String>> loadByUrl(String url, String method) {
                log.error(String.format("资源加载失败-获取URL角色权限 url:%s,method:%s",url,method));
                return ApiResponse.INSTANCE.error(ApiCode.SERVER_ERROR,"资源加载失败");
            }
        };
    }
}
