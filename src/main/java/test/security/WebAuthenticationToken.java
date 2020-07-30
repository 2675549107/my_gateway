package test.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @description 后台身份认证类
 * @author LGZ
 * @description
 * @create_date 2020/2/13 15:49
 */
public class WebAuthenticationToken extends AbstractAuthenticationToken {
    private final Object principal;
    private Object credentials;
    private Long stationId;


    public WebAuthenticationToken(Object principal, Object credentials, Long stationId) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        this.stationId = stationId;
        setAuthenticated(false);
    }

    public WebAuthenticationToken(Object principal, Object credentials, Long stationId,
                                  Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.stationId = stationId;
        this.credentials = credentials;
        // must use super, as we override
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }

    public Long getStationId() {
        return this.stationId;
    }
}
