package io.airlift.security.authentication.client;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.eclipse.jetty.client.api.Authentication;
import org.eclipse.jetty.client.api.AuthenticationStore;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

public class ExtendedAuthenticationStore implements AuthenticationStore
{
    private final List<Authentication> authentications = new CopyOnWriteArrayList<>();

    private final Cache<URI, Authentication.Result> results =
            CacheBuilder.newBuilder().maximumSize(10000).expireAfterWrite(10, TimeUnit.SECONDS).build();

    @Override
    public void addAuthentication(Authentication authentication)
    {
        authentications.add(authentication);
    }

    @Override
    public void removeAuthentication(Authentication authentication)
    {
        authentications.remove(authentication);
    }

    @Override
    public void clearAuthentications()
    {
        authentications.clear();
    }

    @Override
    public Authentication findAuthentication(String type, URI uri, String realm)
    {
        for (Authentication authentication : authentications)
        {
            if (authentication.matches(type, uri, realm))
                return authentication;
        }
        return null;
    }

    @Override
    public void addAuthenticationResult(Authentication.Result result)
    {
        results.put(result.getURI(), result);
    }

    @Override
    public void removeAuthenticationResult(Authentication.Result result)
    {
        results.invalidate(result.getURI());
    }

    @Override
    public void clearAuthenticationResults()
    {
        results.invalidateAll();
    }

    @Override
    public Authentication.Result findAuthenticationResult(URI uri)
    {
        // TODO: I should match the longest URI
        for (Map.Entry<URI, Authentication.Result> entry : results.asMap().entrySet())
        {
            if (uri.toString().startsWith(entry.getKey().toString()))
                return entry.getValue();
        }
        return null;
    }
}
