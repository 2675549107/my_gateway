package test.config;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.Min;
import java.io.Serializable;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 11:19 2020/6/19
 */
@Data
@ApiModel(value = "分页信息")
public class BasePage implements Serializable {


    private static final long serialVersionUID = -7993194659326656676L;

    @Min(
            value = 1L,
            message = "当前页必须大于零"
    )
    @ApiModelProperty("当前页码，从1开始，默认为1")
    private long page = 1;


    @Min(
            value = 1L,
            message = "每页显示条数必须大于零"
    )
    @ApiModelProperty(value = "每页大小  默认为10")
    private long limit = 10;

    public BasePage() {
    }

    public BasePage(@Min(
            value = 1L,
            message = "当前页必须大于零"
    ) long page, @Min(
            value = 1L,
            message = "每页显示条数必须大于零"
    ) long limit) {
        this.page = page;
        this.limit = limit;
    }

    /**
     * 转换为mybatis-plus分页所需
     *
     * @param <T> 所需类型
     * @return 分页信息
     */
    public <T> Page<T> toPage() {
        return new Page<>(this.page, this.limit, true);
    }

    /**
     * 验证当前属性信息
     */
    public void verify() {
        if (this.page < 1) {
            this.page = 1;
        }
        if (this.limit < 1) {
            this.limit = 10;
        }
    }
}
