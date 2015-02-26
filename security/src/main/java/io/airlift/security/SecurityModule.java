package io.airlift.security;

import com.google.inject.Binder;
import com.google.inject.Key;
import io.airlift.configuration.ConfigurationAwareModule;
import io.airlift.configuration.ConfigurationFactory;
import io.airlift.configuration.ConfigurationProvider;
import org.apache.shiro.web.env.EnvironmentLoaderListener;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

public class SecurityModule implements ConfigurationAwareModule
{
    private ConfigurationFactory configurationFactory;

    @Override
    public void setConfigurationFactory(ConfigurationFactory configurationFactory)
    {
        this.configurationFactory = checkNotNull(configurationFactory, "configurationFactory is null");
    }

    @Override
    public void configure(Binder binder)
    {
        checkState(configurationFactory != null, "configurationFactory was not set");
        binder.bind(AuthConfig.class).toProvider(new ConfigurationProvider<AuthConfig>(Key.get(AuthConfig.class), AuthConfig.class, null));
        AuthConfig authConfig = configurationFactory.build(AuthConfig.class);
        if (shouldBind(authConfig)) {
            binder.bind(EnvironmentLoaderListener.class).annotatedWith(Security.class).to(SecurityEnvironmentLoaderListener.class);
        }
    }

    private boolean shouldBind(AuthConfig authConfig)
    {
        return authConfig.getAuthSchemes() != null && ! authConfig.getAuthSchemes().isEmpty();
    }
}
