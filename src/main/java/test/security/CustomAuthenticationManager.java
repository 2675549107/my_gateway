
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
            List<String> roles = null;
            //如果是WEB端 则会去加载对应角色
            if (authentication.getClass().isAssignableFrom(WebAuthenticationToken.class)) {
                WebAuthenticationToken token = (WebAuthenticationToken) authentication;
                if(token.getRoleId()!=null){
                    ApiResult<List<String>> apiResult = userCenterApiClient.findRoleByStationId(token.getRoleId());
                    if (apiResult.getCode() == HttpStatus.OK.value()) {
                        if(!CollectionUtils.isEmpty(apiResult.getData())){
                            roles=apiResult.getData().stream().map(n-> GlobalConstant.AUTH_PREFIX+n).collect(Collectors.toList());
                        }
                    }else{
                        log.error(String.format("远程调用失败:{user_center:findRoleByAccount:account=%s}",authentication.getName()));
                    }
                }
            }
            if(roles==null){
                roles=new ArrayList<>();
            }
            roles.add(GlobalConstant.AUTH_ROLE_USER);
            authentication = new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(),
                    roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
            );
        }
        return Mono.just(authentication);


    }
}
