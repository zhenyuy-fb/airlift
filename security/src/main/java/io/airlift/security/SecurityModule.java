package io.airlift.security;

import com.google.inject.Binder;
import com.google.inject.multibindings.Multibinder;
import io.airlift.configuration.ConfigurationAwareModule;
import io.airlift.configuration.ConfigurationFactory;
import io.airlift.http.server.TheServlet;
import io.airlift.security.authentication.server.ExtendedShiroFilter;
import io.airlift.security.config.ServerSecurityConfig;

import javax.servlet.Filter;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

public class SecurityModule
        implements ConfigurationAwareModule
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
        if (serverSecurityConfig.enabled()) {
            Filter spnegoFilter = new ExtendedShiroFilter(serverSecurityConfig);
            Multibinder.newSetBinder(binder, Filter.class, TheServlet.class).addBinding().toInstance(spnegoFilter);
        }
    }
}
