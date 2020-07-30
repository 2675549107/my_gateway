package test.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 自定义权限认证类  改变原来单角色对应多资源的比对  改从能访问资源的权限集合
 * @author LGZ
 * @create_date 2020年1月7日16:46:16
 * @param <T>
 */
@Slf4j
public class CustomAuthorityReactiveAuthorizationManager<T> implements ReactiveAuthorizationManager<T> {

	//资源对应权限集合
	private final List<String> authority;

	private CustomAuthorityReactiveAuthorizationManager(List<String> authority) {
		this.authority = authority;
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		return authentication
			.filter(Authentication::isAuthenticated)
			.flatMapIterable(Authentication::getAuthorities)
			.map(GrantedAuthority::getAuthority).any(n->authority.stream().anyMatch(n::equals))
			.map( hasAuthority -> new AuthorizationDecision(hasAuthority))
			.defaultIfEmpty(new AuthorizationDecision(false));
	}

	public static <T> CustomAuthorityReactiveAuthorizationManager<T> hasAuthority(List<String> authority) {
		Assert.notNull(authority, "authority cannot be null");
		log.info("当前URL所需权限:{}",authority);
		return new CustomAuthorityReactiveAuthorizationManager<>(authority);
	}
	public static <T> CustomAuthorityReactiveAuthorizationManager<T> hasRole(List<String> roles) {
		//权限前缀添加ROLE_  SpringSecurity中ROLE的规范
		Assert.notNull(roles, "authority cannot be null");
		return hasAuthority(roles.stream().map(n->"ROLE_"+n).collect(Collectors.toList()));
	}
}
