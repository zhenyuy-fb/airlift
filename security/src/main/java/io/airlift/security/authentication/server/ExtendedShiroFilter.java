package io.airlift.security.authentication.server;

import io.airlift.security.authentication.AuthScheme;
import io.airlift.security.config.ServerSecurityConfig;
import io.airlift.security.realm.SpnegoRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class ExtendedShiroFilter
        extends AbstractShiroFilter
{
    private static final String SPNEGO_REALM_NAME = "spnego-realm";
    private static final String SPNEGO_FILTER_NAME = "spnego-filter";
    private final ServerSecurityConfig serverSecurityConfig;

    public ExtendedShiroFilter(ServerSecurityConfig serverSecurityConfig)
    {
        checkNotNull(serverSecurityConfig, "serverSecurityConfig is null");
        this.serverSecurityConfig = serverSecurityConfig;
    }

    @Override
    public void init()
            throws Exception
    {
        setSecurityManager(getSecurityManager(serverSecurityConfig));
        setFilterChainResolver(getSecurityFilterChainResolver(serverSecurityConfig));
    }

    @Override
    protected FilterChain getExecutionChain(ServletRequest request, ServletResponse response, FilterChain origChain)
    {
        if (request.isSecure()) {
            return super.getExecutionChain(request, response, origChain);
        }
        return origChain;
    }

    private WebSecurityManager getSecurityManager(ServerSecurityConfig serverSecurityConfig)
    {
        Realm spnegoRealm = new SpnegoRealm(SPNEGO_REALM_NAME, serverSecurityConfig.getServiceName(), serverSecurityConfig.getKrb5Conf());
        WebSecurityManager webSecurityManager = new DefaultWebSecurityManager(spnegoRealm);
        return webSecurityManager;
    }

    private FilterChainResolver getSecurityFilterChainResolver(ServerSecurityConfig serverSecurityConfig)
    {
        FilterChainManager filterChainManager = new DefaultFilterChainManager();
        if (serverSecurityConfig.enabled()) {
            List<AuthScheme> authSchemes = serverSecurityConfig.getAuthSchemes();
            checkArgument(authSchemes != null && !authSchemes.isEmpty(), "authSchemes is null or empty");

            for (AuthScheme scheme : serverSecurityConfig.getAuthSchemes()) {
                switch (scheme) {
                    case NEGOTIATE:
                        //set filter chain resolver
                        SpnegoAuthenticationFilter spnegoAuthenticationFilter = new SpnegoAuthenticationFilter();
                        filterChainManager.addFilter(SPNEGO_FILTER_NAME, spnegoAuthenticationFilter);
                        filterChainManager.createChain("/**", SPNEGO_FILTER_NAME);
                        break;
                    default:
                        // do nothing
                        break;
                }
            }
        }
        if (!filterChainManager.getChainNames().isEmpty()) {
            PathMatchingFilterChainResolver filterChainResolver = new PathMatchingFilterChainResolver();
            filterChainResolver.setFilterChainManager(filterChainManager);
            return filterChainResolver;
        }
        return null;
    }
}
