package io.airlift.security;

import com.google.common.base.Strings;
import io.airlift.security.authentication.SpnegoAuthenticationFilter;
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

import java.io.File;

import static com.google.common.base.Preconditions.checkArgument;

@WebListener
public class SecurityEnvironmentLoaderListener extends EnvironmentLoaderListener implements ServletContextListener
{
    public static final String SPNEGO_FILTER = "spnego-filter";
    public static final String SPNEGO_REALM = "spnego-realm";
    private final AuthConfig authConfig;

    @Inject
    public SecurityEnvironmentLoaderListener(AuthConfig authConfig)
    {
        this.authConfig = authConfig;
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
            MutableWebEnvironment webEnvironment = (MutableWebEnvironment)environment;

            if (authConfig.getAuthSchemes() != null) {
                for (AuthConfig.AuthScheme scheme : authConfig.getAuthSchemes()) {
                    switch (scheme) {
                        case NEGOTIATE:
                            checkArgument(!Strings.isNullOrEmpty(authConfig.getServiceName()));
                            checkArgument(!Strings.isNullOrEmpty(authConfig.getKrb5Conf()));
                            checkArgument((new File(authConfig.getKrb5Conf())).exists());

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

    }

    private WebSecurityManager getWebSecurityManager()
    {
        Realm spnegoRealm = new SpnegoRealm(SPNEGO_REALM, authConfig.getServiceName(), authConfig.getKrb5Conf());
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
