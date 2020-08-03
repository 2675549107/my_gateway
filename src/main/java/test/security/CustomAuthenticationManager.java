
package test.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Mono;
import test.config.ApiResult;
import test.config.GlobalConstant;
import test.feign.UserCenterApiClient;
import test.pojo.vo.RoleVO;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class CustomAuthenticationManager implements ReactiveAuthenticationManager {

    @Lazy
    @Autowired
    private UserCenterApiClient userCenterApiClient;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {


        //未登录状态
        if (authentication.getClass().isAssignableFrom(AnonymousAuthenticationToken.class)) {
            authentication.setAuthenticated(false);
        } else {
            List<String> roles = new ArrayList<>();
            //如果是WEB端 则会去加载对应角色
            if (authentication.getClass().isAssignableFrom(WebAuthenticationToken.class)) {
                WebAuthenticationToken token = (WebAuthenticationToken) authentication;
                if(token.getRoleId()!=null){
                    ApiResult<RoleVO> apiResult = userCenterApiClient.findRoleById(token.getRoleId());
                    if (apiResult.getCode() == HttpStatus.OK.value()) {
                        if(apiResult.getData() != null){
                            roles.add("ROLE" + apiResult.getData().getSecurityName());
                        }
                    }else{
                        log.error(String.format("远程调用失败:{user_center:findRoleByAccount:account=%s}",authentication.getName()));
                    }
                }
            }
            if(roles==null){
                roles=new ArrayList<>();
            }
            //如果登录了，但是没有任何角色，默认放置个USER角色
            roles.add(GlobalConstant.AUTH_ROLE_USER);
            authentication = new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(),
                    roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
            );
        }
        return Mono.just(authentication);
    }
}
