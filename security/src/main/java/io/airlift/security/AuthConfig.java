package io.airlift.security;

import com.google.common.collect.ImmutableList;
import io.airlift.configuration.Config;

import java.util.List;

public class AuthConfig
{
    private List<AuthScheme> authSchemes;
    private String krb5Conf;
    private String serviceName;
    public static final String DELIMITER = ",";

    public enum AuthScheme
    {
        NEGOTIATE
    }

    public List<AuthScheme> getAuthSchemes() { return authSchemes; }

    @Config("http-security.https.authentication.enabled-schemes")
    public AuthConfig setAuthSchemes(String authSchemesStr)
    {
        if(authSchemesStr != null && authSchemesStr.length() > 0) {
            ImmutableList.Builder<AuthScheme> builder = ImmutableList.builder();
            String[] schemes = authSchemesStr.split(DELIMITER);
            for (String scheme : schemes) {
                try {
                    builder.add(AuthScheme.valueOf(scheme.toUpperCase()));
                } catch (IllegalArgumentException ex) {
                    throw new IllegalArgumentException(String.format("Unrecognized authentication scheme %s", scheme));
                }
            }
            authSchemes = builder.build();
        }
        return this;
    }

    public String getKrb5Conf() { return krb5Conf; }

    @Config("http-security.https.authentication.negotiate.krb5conf")
    public AuthConfig setKrb5Conf(String krb5Conf)
    {
        this.krb5Conf = krb5Conf;
        return this;
    }

    public String getServiceName() { return serviceName; }

    @Config("http-server.https.authentication.negotiate.service-name")
    public AuthConfig setServiceName(String serviceName)
    {
        this.serviceName = serviceName;
        return this;
    }
}
