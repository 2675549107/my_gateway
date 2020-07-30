package test.feign;

import feign.hystrix.FallbackFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import test.config.ApiCode;
import test.config.ApiResult;
import test.utils.enums.ApiResponse;

import java.util.List;

/**
 * <p> ExhibitionApi 客户端错误处理 </p>
 *
 * @author LGZ
 * @version 1.0
 * @create_date 2020年1月3日14:45:24
 */
@Component
@Slf4j
public class UserCenterApiClientFallbackFactory implements FallbackFactory<UserCenterApiClient> {

    @Override
    public UserCenterApiClient create(Throwable cause) {
        cause.printStackTrace();
        return new UserCenterApiClient(){
            @Override
            public ApiResult<List<String>> findRoleByStationId(Long stationId) {
                log.error("获取用户角色-资源加载失败 stationId:{}",stationId);
                log.error("获取用户角色-资源加载失败 stationId:{}",stationId);
                return ApiResponse.INSTANCE.error(ApiCode.SERVER_ERROR,"服务繁忙，请稍后再试");
            }
        };
    }
}
