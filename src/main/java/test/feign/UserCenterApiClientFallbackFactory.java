package test.feign;

import feign.hystrix.FallbackFactory;
import lombok.extern.slf4j.Slf4j;
import net.iotcd.api.sdk.core.result.ApiCode;
import net.iotcd.api.sdk.core.result.ApiResponse;
import net.iotcd.api.sdk.core.result.ApiResult;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestParam;
import test.pojo.vo.RoleVO;

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
            public ApiResult<RoleVO> findRoleById(@RequestParam("roleId") Long roleId) {
                log.error("获取用户角色-资源加载失败 roleId:{}",roleId);
                log.error("获取用户角色-资源加载失败 roleId:{}",roleId);
                return ApiResponse.INSTANCE.error(ApiCode.SERVER_ERROR,"服务繁忙，请稍后再试");
            }
        };
    }
}
