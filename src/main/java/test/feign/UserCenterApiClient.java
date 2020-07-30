package test.feign;

import io.swagger.annotations.ApiOperation;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import test.config.ApiResult;

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
     * @param stationId
     * @return
     */
    @GetMapping("user/manage/loadRoleByStation")
    @ApiOperation("智会云系统加载用户角色")
    ApiResult<List<String>> findRoleByStationId(@RequestParam("stationId") Long stationId);
}
