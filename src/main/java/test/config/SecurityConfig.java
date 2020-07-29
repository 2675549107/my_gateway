package test.config;

import com.alibaba.fastjson.JSONObject;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
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
import test.utils.JwtTokenUtils;
import test.utils.enums.ApiResponse;

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
            "/ucenter-web/login",
    };

    /**
     * 小程序不需要拦截的路径
     */
    private static final String[] APP_AUTH_WHITELIST = new String[]{"/**/app/**", "/**/applet/**"};

    @Autowired
    private CustomAuthenticationManager customAuthenticationManager;
    @Autowired
    private ResourceAuthApiClient resourceAuthApiClient;

    @Autowired
    private JwtTokenUtils jwtTokenUtils;

    /**
     * security 配置
     *
     * @author sunmj
     * @date 2019/11/19
     */
    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        /**
         * 从上到下，依次是：
         *      1.关闭spring security的csrf跨域保护（这里使用gate way的跨域保护）
         *      2.关闭spring security默认的登录页面（我们使用单点登录系统登录）
         *      3.关闭基本认证（我们使用token认证）
         *      4.认证失败，抛异常
         *      5.具体异常一：访问没有权限
         */
        return http.csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .exceptionHandling()
                //访问没有权限
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
                String tokenType = claimsFromToken.get("type", String.class);
                //小程序用户Token
                Long userId = claimsFromToken.get(HeaderConstant.USER_ID, Long.class);
                Map<String, String> headerMap = new HashMap<>(4);

                Long stationId = claimsFromToken.get(HeaderConstant.STATION_ID, Long.class);
                Long departmentId = claimsFromToken.get(HeaderConstant.DEPARTMENT_ID, Long.class);
                Authentication authentication;
                switch (tokenType) {
                    case TokenTypeConstant.APPLET: {
                        Long userAppletId = claimsFromToken.get(HeaderConstant.USER_APPLET_ID, Long.class);
                        headerMap.put(HeaderConstant.USER_APPLET_ID, userAppletId == null ? "" : userAppletId.toString());
                        headerMap.put(HeaderConstant.TOKEN_TYPE, TokenTypeConstant.APPLET);
                        headerMap.put(HeaderConstant.USER_ID, userId == null ? "" : userId.toString());
                        headerMap.put(HeaderConstant.STATION_ID, stationId == null ? "" : stationId.toString());
                        headerMap.put(HeaderConstant.DEPARTMENT_ID, departmentId == null ? "" : departmentId.toString());
                        authentication = new AppletAuthenticationToken(accountNameFromToken, token);
                        break;
                    }
                    case TokenTypeConstant.WEB: {
                        Long userManageId = claimsFromToken.get(HeaderConstant.USER_MANAGE_ID, Long.class);
                        headerMap.put(HeaderConstant.USER_ID, userId == null ? "" : userId.toString());
                        headerMap.put(HeaderConstant.STATION_ID, stationId == null ? "" : stationId.toString());
                        headerMap.put(HeaderConstant.USER_MANAGE_ID, userManageId == null ? "" : userManageId.toString());
                        headerMap.put(HeaderConstant.DEPARTMENT_ID, departmentId == null ? "" : departmentId.toString());
                        headerMap.put(HeaderConstant.TOKEN_TYPE, TokenTypeConstant.WEB);
                        //处理超级管理员
                        if (stationId != null && stationId.equals(-1L)) {
                            exchange.getResponse().getHeaders().set(GlobalConstant.ROLE_KEY, GlobalConstant.AUTH_ROLE_ADMIN);
                        }
                        authentication = new WebAuthenticationToken(accountNameFromToken, token, stationId);
                        break;
                    }
                    default: {
                        exchange.getResponse().getHeaders().set(GlobalConstant.ROLE_KEY, GlobalConstant.AUTH_ROLE_ANONYMOUS);
                        authentication = anonymous;
                        break;
                    }
                }
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

            //放行OPTIONS请求（预检请求，正式请求发起前的探路请求）
            if (CorsUtils.isPreFlightRequest(exchange.getRequest())) {
                return chain.filter(exchange);
            }

            //处理url不需要身份验证
            List<Boolean> flag = new ArrayList<>();
            ServerWebExchangeMatchers.pathMatchers(AUTH_WHITELIST)
                    .matches(exchange)
                    .map(ServerWebExchangeMatcher.MatchResult::isMatch)
                    .subscribe(flag::add);

            //处理如果是app的请求 则校验app的白名单
            String type = exchange.getRequest().getHeaders().getFirst(HeaderConstant.TOKEN_TYPE);
            if (StringUtils.isNotBlank(type) && type.equals(TokenTypeConstant.APPLET)) {
                ServerWebExchangeMatchers.pathMatchers(APP_AUTH_WHITELIST).matches(exchange).map(ServerWebExchangeMatcher.MatchResult::isMatch).subscribe(flag::add);
            }
            //这里判断了是否是白名单路径
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
                    //判断身份为游客并且请求不在白名单的时候 则抛出异常提示登录
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
            //处理url传参的情况（把/1这种以/{id}代替）（因为角色能否访问一个页面是通过url决定的，这里解决/xx/1这种url匹配的角色）
            String replacePath = path.replaceAll("/[\\-0-9]+", "/{id}");


            //处理验证是web 还是 app
            String tokenType = exchange.getRequest().getHeaders().getFirst(HeaderConstant.TOKEN_TYPE);
            if (StringUtils.isBlank(tokenType)) {
                log.error("TOKEN_TYPE 为空");
                throw new AuthenticationCredentialsNotFoundException("UNAUTHORIZED");
            }
            List<String> roles;
            //请求获取当前url 需要的角色
            ApiResult<List<String>> apiResult;
            if (tokenType.equals(TokenTypeConstant.APPLET)) {
                apiResult = resourceAuthApiClient.loadByUrl(replacePath, method.name(), ResourceAuthClientTypeEnum.APP, systemType);
            } else {
                apiResult = resourceAuthApiClient.loadByUrl(replacePath, method.name(), ResourceAuthClientTypeEnum.WEB, systemType);
            }
            if (apiResult.getCode() != HttpStatus.OK.value()) {
                log.error("远程调用失败:loadByUrl:param={},{}", replacePath, method.name());
                roles = new ArrayList<>();
            } else {
                roles = apiResult.getData();
            }
            if (roles.isEmpty()) {
                //如果没找到URL对应权限 默认需要用户登录后才能访问
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
     * 当用户访问了自己角色没有权限的路径时，则会调用此方法
     * accessDeniedHandler   没有权限的Response
     */
    ServerAccessDeniedHandler accessDeniedHandler() {

        return (exchange, denied) -> Mono.defer(() -> Mono.just(exchange.getResponse()))
                .flatMap(response -> {
                    //返回http的状态码：200
                    response.setStatusCode(HttpStatus.OK);
                    //返回json的contentType
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON_UTF8);
                    List<String> origin = exchange.getRequest().getHeaders().get("Origin");
                    if (!CollectionUtils.isEmpty(origin)) {
                        /**
                         * 如果防跨域请求不是空的，但是又进入了此方法，请求不在防跨域请求的范围内，给出服务器
                         * 请求跨域的范围
                         */
                        response.getHeaders().addAll("Access-Control-Allow-Origin", origin);
                        response.getHeaders().add("Access-Control-Allow-Headers", GlobalConstant.ACCESS_CONTROL_ALLOW_HEADERS);
                        response.getHeaders().add("Access-Control-Allow-Methods", GlobalConstant.ACCESS_CONTROL_ALLOW_METHODS);
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
     * serverAuthenticationEntryPoint   未认证的Response(没有登录的)
     */
    ServerAuthenticationEntryPoint serverAuthenticationEntryPoint() {

        return (exchange, e) -> Mono.defer(() -> Mono.just(exchange.getResponse()))
                .flatMap(response -> {
                    //遇到未认证时返回http代码200
                    response.setStatusCode(HttpStatus.OK);
                    //设置httpd额contentType
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON_UTF8);
                    List<String> origin = exchange.getRequest().getHeaders().get("Origin");
                    /**
                     * 如果防跨域请求不是空的，但是又进入了此方法，请求不在防跨域请求的范围内，给出服务器
                     * 请求跨域的范围
                     */
                    if (!CollectionUtils.isEmpty(origin)) {
                        response.getHeaders().addAll("Access-Control-Allow-Origin", origin);
                        response.getHeaders().add("Access-Control-Allow-Headers", GlobalConstant.ACCESS_CONTROL_ALLOW_HEADERS);
                        response.getHeaders().add("Access-Control-Allow-Methods", GlobalConstant.ACCESS_CONTROL_ALLOW_METHODS);
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