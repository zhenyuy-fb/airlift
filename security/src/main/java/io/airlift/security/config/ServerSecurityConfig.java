package io.airlift.security.config;

import com.google.common.collect.ImmutableList;
import io.airlift.configuration.Config;
import io.airlift.security.authentication.AuthScheme;

import java.util.List;

import static java.lang.String.format;

public class ServerSecurityConfig extends SecurityConfig
{
    private List<AuthScheme> authSchemes;
    private String krb5Conf;
    private String serviceName;
    public static final String DELIMITER = ",";

    public List<AuthScheme> getAuthSchemes() { return authSchemes; }

    @Config("http-security.server.https.authentication.enabled-schemes")
    public ServerSecurityConfig setAuthSchemes(String authSchemesStr)
    {
        if(authSchemesStr != null && authSchemesStr.length() > 0) {
            ImmutableList.Builder<AuthScheme> builder = ImmutableList.builder();
            String[] schemes = authSchemesStr.split(DELIMITER);
            for (String scheme : schemes) {
                try {
                    builder.add(AuthScheme.valueOf(scheme.toUpperCase()));
                } catch (IllegalArgumentException ex) {
                    throw new IllegalArgumentException(format("Unrecognized authentication scheme %s", scheme));
                }
            }
            authSchemes = builder.build();
        }
        return this;
    }

    public String getKrb5Conf() { return krb5Conf; }

    @Config("http-security.server.https.authentication.negotiate.krb5conf")
    public ServerSecurityConfig setKrb5Conf(String krb5Conf)
    {
        this.krb5Conf = krb5Conf;
        return this;
    }

    public String getServiceName() { return serviceName; }

    @Config("http-security.server.https.authentication.negotiate.service-name")
    public ServerSecurityConfig setServiceName(String serviceName)
    {
        this.serviceName = serviceName;
        return this;
    }

    public boolean enabled()
    {
        return authSchemes != null  || krb5Conf != null || serviceName != null;
    }
}
