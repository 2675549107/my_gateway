package test.config;

import com.baomidou.mybatisplus.core.metadata.IPage;
import lombok.Data;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * @Author: WuDi
 * @Description:
 * @Date: Created in 11:16 2020/6/19
 */
@Data
public class PageResult<T> implements Serializable {

    /**
     * 列表数据
     */
    private List<T> data;

    /**
     * 页数
     */
    private long page;

    /**
     * 每页条数
     */
    private long limit;

    /**
     * 总数
     */
    private long total;

    public PageResult() {

    }

    public PageResult(IPage<T> page) {
        this.data = page.getRecords();
        if (this.data == null) {
            this.data = new ArrayList<>(0);
        }
        this.page = (int) page.getCurrent();
        this.limit = (int) page.getSize();
        this.total = page.getTotal();
    }

    public PageResult(List<T> data, long page, long limit, long total) {
        this.data = data;
        if (this.data == null) {
            this.data = new ArrayList<>(0);
        }
        this.page = page;
        this.limit = limit;
        this.total = total;
    }

    public PageResult(List<T> data, IPage page) {
        this.data = data;
        if (this.data == null) {
            this.data = new ArrayList<>(0);
        }
        this.page = (int) page.getCurrent();
        this.limit = (int) page.getSize();
        this.total = page.getTotal();
    }
}
