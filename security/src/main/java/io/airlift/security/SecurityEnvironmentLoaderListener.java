package io.airlift.security;

import io.airlift.security.authentication.AuthScheme;
import io.airlift.security.authentication.server.SpnegoAuthenticationFilter;
import io.airlift.security.config.ServerSecurityConfig;
import io.airlift.security.realm.SpnegoRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.env.DefaultWebEnvironment;
import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.env.MutableWebEnvironment;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.inject.Inject;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

@WebListener
public class SecurityEnvironmentLoaderListener
        extends EnvironmentLoaderListener
        implements ServletContextListener
{
    public static final String SPNEGO_FILTER = "spnego-filter";
    public static final String SPNEGO_REALM = "spnego-realm";
    private final ServerSecurityConfig serverSecurityConfig;

    @Inject
    public SecurityEnvironmentLoaderListener(ServerSecurityConfig serverSecurityConfig)
    {
        checkNotNull(serverSecurityConfig, "securityServerConfig is null");
        List<AuthScheme> authSchemes = serverSecurityConfig.getAuthSchemes();
        checkArgument(authSchemes != null && !authSchemes.isEmpty(), "authSchemes is null or empty");
        this.serverSecurityConfig = serverSecurityConfig;
    }

    @Override
    public void contextInitialized(ServletContextEvent sce)
    {
        sce.getServletContext().setInitParameter(ENVIRONMENT_CLASS_PARAM, DefaultWebEnvironment.class.getName());
        super.contextInitialized(sce);
    }

    @Override
    protected void customizeEnvironment(WebEnvironment environment)
    {
        if (environment instanceof MutableWebEnvironment) {
            MutableWebEnvironment webEnvironment = (MutableWebEnvironment) environment;

            for (AuthScheme scheme : serverSecurityConfig.getAuthSchemes()) {
                switch (scheme) {
                    case NEGOTIATE:
                        // set security manager and filter chain resolver
                        webEnvironment.setWebSecurityManager(getWebSecurityManager());
                        webEnvironment.setFilterChainResolver(getFilterChainResolver());
                        break;
                    default:
                        // do nothing
                        break;
                }
            }
        }
    }

    private WebSecurityManager getWebSecurityManager()
    {
        Realm spnegoRealm = new SpnegoRealm(SPNEGO_REALM, serverSecurityConfig.getServiceName(), serverSecurityConfig.getKrb5Conf());
        WebSecurityManager webSecurityManager = new DefaultWebSecurityManager(spnegoRealm);
        return webSecurityManager;
    }

    private FilterChainResolver getFilterChainResolver()
    {
        SpnegoAuthenticationFilter spnegoAuthenticationFilter = new SpnegoAuthenticationFilter();
        FilterChainManager filterChainManager = new DefaultFilterChainManager();
        filterChainManager.addFilter(SPNEGO_FILTER, spnegoAuthenticationFilter);
        filterChainManager.createChain("/**", SPNEGO_FILTER);
        PathMatchingFilterChainResolver filterChainResolver = new PathMatchingFilterChainResolver();
        filterChainResolver.setFilterChainManager(filterChainManager);
        return filterChainResolver;
    }
}
