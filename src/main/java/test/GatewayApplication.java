package test;

import net.iotcd.api.sdk.core.config.exception.BaseHandlerException;
import net.iotcd.api.sdk.core.config.swagger.BaseSwaggerConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;

/**
 * 网关启动类
 *
 * @author lieber
 * @date 2019-12-18
 */
@SpringBootApplication
@EnableEurekaClient
@EnableFeignClients(value = "test.feign")
@ComponentScan(value = {"test"},excludeFilters = {
        @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,classes = {BaseHandlerException.class}),
        @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,classes = {BaseSwaggerConfig.class})
})
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

}
