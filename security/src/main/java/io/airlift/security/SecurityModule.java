package io.airlift.security;

import com.google.inject.Binder;
import com.google.inject.Key;
import io.airlift.configuration.ConfigurationAwareModule;
import io.airlift.configuration.ConfigurationFactory;
import io.airlift.configuration.ConfigurationProvider;
import io.airlift.security.config.ServerSecurityConfig;
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
        ServerSecurityConfig serverSecurityConfig = configurationFactory.build(ServerSecurityConfig.class);
        binder.bind(ServerSecurityConfig.class)
                .annotatedWith(Security.class)
                .toProvider(new ConfigurationProvider<>(Key.get(ServerSecurityConfig.class), ServerSecurityConfig.class, null));

        if (serverSecurityConfig.enabled()) {
            binder.bind(EnvironmentLoaderListener.class).annotatedWith(Security.class).to(SecurityEnvironmentLoaderListener.class);
        }
    }
}
