package io.airlift.security.authentication.client;

import com.google.common.collect.ImmutableList;
import io.airlift.security.config.ClientSecurityConfig;
import org.eclipse.jetty.client.api.Authentication;

import java.net.URI;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticationProvider
{
    private final ClientSecurityConfig clientSecurityConfig;
    private final URI serviceUri;
    private final List<Authentication> authentications = ImmutableList.of();

    public AuthenticationProvider(ClientSecurityConfig clientSecurityConfig, URI serviceUri)
    {
        checkNotNull(clientSecurityConfig, "securityClientConfig is null");
        checkNotNull(clientSecurityConfig.getAuthScheme(), "authScheme is null");
        checkNotNull(serviceUri, "serviceUri is null");
        this.clientSecurityConfig = clientSecurityConfig;
        this.serviceUri = serviceUri;
    }

    public List<Authentication> getAuthentications()
    {
        switch (clientSecurityConfig.getAuthScheme()) {
            case NEGOTIATE:
                SpnegoAuthentication spengoAuthentication = new SpnegoAuthentication(clientSecurityConfig, serviceUri);
                authentications.add(spengoAuthentication);
                break;
            default:
                // do nothing
                break;
        }
        return ImmutableList.copyOf(authentications);
    }
}
