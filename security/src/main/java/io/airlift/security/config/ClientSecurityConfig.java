package io.airlift.security.config;

import io.airlift.configuration.Config;
import io.airlift.security.authentication.AuthScheme;

public class ClientSecurityConfig extends SecurityConfig
{
    private AuthScheme authScheme;
    private String krb5Conf;
    private String serviceName;

    public AuthScheme getAuthScheme() { return authScheme; }

    @Config("http-security.client.authentication.scheme")
    public ClientSecurityConfig setAuthScheme(AuthScheme authScheme)
    {
        this.authScheme = authScheme;
        return this;
    }

    public String getKrb5Conf() { return krb5Conf; }

    @Config("http-security.client.authentication.negotiate.krb5conf")
    public ClientSecurityConfig setKrb5Conf(String krb5Conf)
    {
        this.krb5Conf = krb5Conf;
        return this;
    }

    public String getServiceName() { return serviceName; }

    @Config("http-security.client.authentication.negotiate.service-name")
    public ClientSecurityConfig setServiceName(String serviceName)
    {
        this.serviceName = serviceName;
        return this;
    }

    public boolean enabled()
    {
        return authScheme != null || krb5Conf != null || serviceName != null;
    }
}
