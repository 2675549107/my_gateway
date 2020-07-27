package test.config;

/**
 * BasePage工具类
 *
 * @author luobowen
 * @version 1.0
 * @date 2020/1/2 14:33
 */
public class BasePageUtils {
    /**
     * 工具类：处理空页码和无效页码
     *
     * @param basePage
     * @return basePage
     */
    public static BasePage makePage(BasePage basePage) {
        if (basePage == null) {
            basePage = new BasePage();
            basePage.setPage(1);
            basePage.setLimit(10);
            return basePage;
        }
        if (basePage.getPage() < 1) {
            basePage.setPage(1);
        }
        if (basePage.getLimit() < 1) {
            basePage.setLimit(10);
        }
        return basePage;
    }
}
