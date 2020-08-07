package test.config;

import com.alibaba.fastjson.JSONObject;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import net.iotcd.api.sdk.core.result.ApiCode;
import net.iotcd.api.sdk.core.result.ApiResponse;
import net.iotcd.api.sdk.core.result.ApiResult;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.util.matcher.*;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;
import test.feign.ResourceAuthApiClient;
import test.security.CustomAuthenticationManager;
import test.security.CustomAuthorityReactiveAuthorizationManager;
import test.security.WebAuthenticationToken;
import test.utils.JwtTokenUtils;


import java.nio.charset.Charset;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author LGZ
 * @description SpringSecurity-WebFlux 配置类
 * @create_date 2020年1月3日17:00:09
 */
@ConfigurationProperties("iotcd.security")
@Slf4j
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    /**
     * 允许的请求头参数
     */
    private static final String ACCESS_CONTROL_ALLOW_HEADERS = "X-Requested-With, Origin, Content-Type, Cookie,Authorization,Access-Token,system_type";

    /**
     * 允许的方法(  "*" 浏览器版本较低的时候不支持)
     */
    private static final String ACCESS_CONTROL_ALLOW_METHODS = "GET,POST,DELETE,PUT,OPTIONS,HEAD,CONNECT,TRACE,PATCH,*";

    /**
     * 配置不需要拦截的地址
     */
    public void setAuthWhiteUrl(List<String> authWhiteUrl) {
        if (authWhiteUrl != null && authWhiteUrl.size() > 0) {
            Collections.addAll(authWhiteUrl, AUTH_WHITELIST);
            authWhiteUrl = authWhiteUrl.stream().distinct().collect(Collectors.toList());
            AUTH_WHITELIST = authWhiteUrl.toArray(new String[]{});
        }
    }

    private static String[] AUTH_WHITELIST = new String[]{
            "/actuator/**",
            "/user-center-server/user/login",
            "/swagger-resources/**",
            "/*/v2/api-docs/**",
            "/swagger-ui.html",
            "/favicon.ico",
            "/webjars/springfox-swagger-ui/**",
            "/page/index/**","/page/callback/**",
            "/user-center-server/open/**"
    };

    @Autowired
    private CustomAuthenticationManager customAuthenticationManager;
    @Autowired
    private ResourceAuthApiClient resourceAuthApiClient;

    @Autowired
    private JwtTokenUtils jwtTokenUtils;

    /**
     * security 配置
     *      1.关闭spring security的csrf跨域保护（这里使用gate way的跨域保护）
     *      2.关闭spring security默认的登录页面（我们使用单点登录系统登录）
     *      3.关闭基本认证（我们使用token认证）
     *      4.认证失败，抛异常
     *      5.具体异常一：访问没有权限
     * @author sunmj
     * @date 2019/11/19
     */
    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        return http.csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                //处理认证异常
                .authenticationEntryPoint(serverAuthenticationEntryPoint())
                .and()
                //认证
                .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                //动态鉴权
                .addFilterAt(accessWebFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
                .authorizeExchange()
                //其他所有的都要认证
                .anyExchange().permitAll()
                .and()
                .build();
    }

    /**
     * 认证具体实现(仅判断token真实性)
     * 如果查出用户是超管或者游客，那么直接在header的ROLE参数中放入其身份，这两种身份的用户将不再
     * 进行动态鉴权（超管直接放行，游客直接抛异常）
     */
    ServerAuthenticationConverter serverAuthenticationConverter() {
        final AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "anonymous", AuthorityUtils.createAuthorityList(GlobalConstant.AUTH_ROLE_ANONYMOUS));
        return exchange -> {
            String token = exchange.getRequest().getHeaders().getFirst(GlobalConstant.HEADER_TOKEN_KEY);
            if (StringUtils.isEmpty(token)) {
                exchange.getResponse().getHeaders().add(GlobalConstant.ROLE_KEY, GlobalConstant.AUTH_ROLE_ANONYMOUS);
                return Mono.just(anonymous);
            }
            String accountNameFromToken;
            //验证token有效性
            try {
                Claims claimsFromToken = jwtTokenUtils.getClaimsFromToken(token);
                accountNameFromToken = claimsFromToken.getSubject();
                Long userId = claimsFromToken.get(HeaderConstant.USER_ID, Long.class);
                Map<String, String> headerMap = new HashMap<>(2);

                Long roleId = claimsFromToken.get(HeaderConstant.ROLE_ID, Long.class);
                Authentication authentication;

                headerMap.put(HeaderConstant.USER_ID, userId == null ? "" : userId.toString());
                headerMap.put(HeaderConstant.ROLE_ID, roleId == null ? "" : roleId.toString());
                //超级管理员
                if (roleId != null && roleId.equals(1L)) {
                    exchange.getResponse().getHeaders().set(GlobalConstant.ROLE_KEY, GlobalConstant.AUTH_ROLE_ADMIN);
                }
                authentication = new WebAuthenticationToken(accountNameFromToken, token, roleId);

                exchange.getRequest().mutate().headers(httpHeaders -> {
                    httpHeaders.setAll(headerMap);
                });
                return Mono.just(authentication);
            } catch (Exception e) {
                log.error(String.format("token解析失败:[token:%s] throw : %s", token, e.getMessage()));
                exchange.getResponse().getHeaders().set(GlobalConstant.ROLE_KEY, GlobalConstant.AUTH_ROLE_ANONYMOUS);
                return Mono.just(anonymous);
            }
        };

    }

    /**
     * 认证
     */
    AuthenticationWebFilter authenticationWebFilter() {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(customAuthenticationManager);
        //配置不需要认证的地址  不会再进CustomAuthenticationManager 不会去查找用户身份
        List<ServerWebExchangeMatcher> matchers = new ArrayList<>(AUTH_WHITELIST.length + 1);
        for (String pattern : AUTH_WHITELIST) {
            matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern, null));
        }
        //添加不处理options请求
        matchers.add(new PathPatternParserServerWebExchangeMatcher("/**", HttpMethod.OPTIONS));
        OrServerWebExchangeMatcher orServerWebExchangeMatcher = new OrServerWebExchangeMatcher(matchers);
        //创建反向匹配器 实现白名单不校验
        NegatedServerWebExchangeMatcher negateWhiteList = new NegatedServerWebExchangeMatcher(orServerWebExchangeMatcher);
        authenticationWebFilter.setRequiresAuthenticationMatcher(negateWhiteList);
        authenticationWebFilter.setServerAuthenticationConverter(serverAuthenticationConverter());
        authenticationWebFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(serverAuthenticationEntryPoint()));
        return authenticationWebFilter;
    }

    /**
     * url动态拦截鉴权
     */
    WebFilter accessWebFilter() {
        return (exchange, chain) -> {

            //放行OPTIONS请求
            if (CorsUtils.isPreFlightRequest(exchange.getRequest())) {
                return chain.filter(exchange);
            }

            //处理url不需要身份验证
            List<Boolean> flag = new ArrayList<>();

            List<ServerWebExchangeMatcher> matchers = new ArrayList<>(AUTH_WHITELIST.length + 1);
            for (String pattern : AUTH_WHITELIST) {
                if(pattern.equals("/smart-dining-server/app/catering-shops/*")){
                    matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern, HttpMethod.GET));
                }else{
                    matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern, null));
                }
            }
            ServerWebExchangeMatchers.matchers(matchers.toArray(new ServerWebExchangeMatcher[matchers.size()]))
//            ServerWebExchangeMatchers.pathMatchers(AUTH_WHITELIST)
                    .matches(exchange)
                    .map(ServerWebExchangeMatcher.MatchResult::isMatch)
                    .subscribe(flag::add);

            boolean matchResultBol = flag.stream().anyMatch(n -> n.equals(true));

            //处理超级管理员
            String headerRole = exchange.getResponse().getHeaders().getFirst(GlobalConstant.ROLE_KEY);
            if (StringUtils.isNotBlank(headerRole)) {
                if (headerRole.equals(GlobalConstant.AUTH_ROLE_ADMIN)) {
                    //移除header中的内容
                    exchange.getResponse().getHeaders().remove(GlobalConstant.ROLE_KEY);
                    log.info("超级管理员 放行");
                    return chain.filter(exchange);
                } else if (headerRole.equals(GlobalConstant.AUTH_ROLE_ANONYMOUS) && !matchResultBol) {
                    //如果是游客身份并且是非白名单的url，判断其是异常登录
                    exchange.getResponse().getHeaders().remove(GlobalConstant.ROLE_KEY);
                    throw new AuthenticationCredentialsNotFoundException("UNAUTHORIZED");
                }
            }

            //放行白名单  以及 APP访问
            if (matchResultBol) {
                return chain.filter(exchange);
            }

            //获取当前访问路径 以及访问方式
            String path = exchange.getRequest().getPath().pathWithinApplication().value();
            HttpMethod method = exchange.getRequest().getMethod();

            //这里需要根据权限  去查询所拥有的URL资源
            DelegatingReactiveAuthorizationManager.Builder builder = DelegatingReactiveAuthorizationManager.builder();

            //hasRole  会加前缀 ROLE_ 然后匹配(ROLE_USER  能匹配上  USER)  -- hasAuthority则是直接根据名字匹配(ROLE_USER  只能匹配上  ROLE_USER)
            //配置当前角色 有哪些权限
            //处理url传参的情况
            String replacePath = path.replaceAll("/[\\-0-9]+", "/{id}");

            List<String> roles;
            //请求获取当前url 需要的角色
            ApiResult<List<String>> apiResult;

            apiResult = resourceAuthApiClient.loadByUrl(replacePath, method.name());

            if (apiResult.getCode() != HttpStatus.OK.value()) {
                log.error("远程调用失败:loadByUrl:param={},{}", replacePath, method.name());
                roles = new ArrayList<>();
            } else {
                roles = apiResult.getData();
            }
            if (roles.isEmpty()) {
                //这里加入的不是用户角色（用户角色在token判断已经加入了，这里加入的是url需要的角色，这里是非白名单，又在表中没有找到
                //此url需要的角色信息，那么默认加入个user角色，必须令其登录才能访问
                roles.add(GlobalConstant.AUTH_USER);
            }

            CustomAuthorityReactiveAuthorizationManager authorityManager = CustomAuthorityReactiveAuthorizationManager.hasRole(roles);
            builder.add(new ServerWebExchangeMatcherEntry(ServerWebExchangeMatchers.pathMatchers(method, path), authorityManager));
            DelegatingReactiveAuthorizationManager manager = builder.build();

            return ReactiveSecurityContextHolder.getContext()
                    .filter(c -> c.getAuthentication() != null)
                    .doOnNext(e -> log.info("当前用户权限" + e.getAuthentication().getAuthorities().toString()))
                    .flatMap(n -> {
                        if (!n.getAuthentication().isAuthenticated()) {
                            return Mono.error(new AuthenticationCredentialsNotFoundException("UNAUTHORIZED"));
                        }
                        return Mono.just(n.getAuthentication());
                    })
                    .as(authentication -> manager.verify(authentication, exchange))
                    .switchIfEmpty(chain.filter(exchange));
        };
    }

    /**
     * 当动态鉴权判定是没有权限的用户访问，将会效用下面函数
     * accessDeniedHandler   没有权限的Response
     */
    ServerAccessDeniedHandler accessDeniedHandler() {

        return (exchange, denied) -> Mono.defer(() -> Mono.just(exchange.getResponse()))
                .flatMap(response -> {
                    response.setStatusCode(HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON_UTF8);
                    List<String> origin = exchange.getRequest().getHeaders().get("Origin");
                    if (!CollectionUtils.isEmpty(origin)) {
                        response.getHeaders().addAll("Access-Control-Allow-Origin", origin);
                        response.getHeaders().add("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
                        response.getHeaders().add("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
                    }
                    DataBufferFactory dataBufferFactory = response.bufferFactory();
                    ApiResult result = ApiResponse.INSTANCE.error(ApiCode.JURISDICTION_ERROR, "未经允许的操作");
                    DataBuffer buffer = dataBufferFactory.wrap(JSONObject.toJSONString(result).getBytes(
                            Charset.defaultCharset()));
                    return response.writeWith(Mono.just(buffer))
                            .doOnError(error -> DataBufferUtils.release(buffer));
                });
    }

    /**
     * 当token认证判定失败，将会调用下面函数
     * serverAuthenticationEntryPoint   未认证的Response
     */
    ServerAuthenticationEntryPoint serverAuthenticationEntryPoint() {

        return (exchange, e) -> Mono.defer(() -> Mono.just(exchange.getResponse()))
                .flatMap(response -> {
                    response.setStatusCode(HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON_UTF8);
                    List<String> origin = exchange.getRequest().getHeaders().get("Origin");
                    if (!CollectionUtils.isEmpty(origin)) {
                        response.getHeaders().addAll("Access-Control-Allow-Origin", origin);
                        response.getHeaders().add("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
                        response.getHeaders().add("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
                    }
                    DataBufferFactory dataBufferFactory = response.bufferFactory();
                    ApiResult result = ApiResponse.INSTANCE.error(ApiCode.AUTHENTICATE_ERROR, "请进行登录授权！");
                    DataBuffer buffer = dataBufferFactory.wrap(JSONObject.toJSONString(result).getBytes(
                            Charset.defaultCharset()));
                    return response.writeWith(Mono.just(buffer))
                            .doOnError(error -> DataBufferUtils.release(buffer));
                });
    }
}