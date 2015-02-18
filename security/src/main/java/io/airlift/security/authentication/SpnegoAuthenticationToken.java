package io.airlift.security.authentication;

import org.apache.shiro.authc.AuthenticationToken;

public class SpnegoAuthenticationToken
        implements AuthenticationToken
{
    // username normally is null since token contains all the info
    private String username;
    private String token;

    public SpnegoAuthenticationToken(String username, String token)
    {
        this.username = username;
        this.token = token;
    }

    public Object getPrincipal() { return username; }

    public Object getCredentials() { return token; }
}
