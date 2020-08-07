package test.feign;

import io.swagger.annotations.ApiOperation;
import net.iotcd.api.sdk.core.result.ApiResult;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import test.pojo.vo.RoleVO;

import java.util.List;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 17:31 2020/7/29
 */
@FeignClient(value = "USER-CENTER-SERVER", fallbackFactory = UserCenterApiClientFallbackFactory.class, path = "user-center-server")
public interface UserCenterApiClient {

    /**
     * 加载用户角色
     * @param roleId
     * @return
     */
    @GetMapping("/user/findRoleById")
    @ApiOperation("智会云系统加载用户角色")
    ApiResult<RoleVO> findRoleById(@RequestParam("roleId") Long roleId);
}
