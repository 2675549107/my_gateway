package test.pojo.vo;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 14:48 2020/8/3
 */
@ApiModel("角色信息")
@Data
public class RoleVO {
    @ApiModelProperty("角色ID")
    private Long id;

    @ApiModelProperty("角色名")
    private String name;

    @ApiModelProperty("spring security使用的名称")
    private String securityName;
}
