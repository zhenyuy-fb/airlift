package io.airlift.security;

import com.google.common.collect.ImmutableMap;
import io.airlift.configuration.testing.ConfigAssertions;
import org.testng.annotations.Test;

import java.util.Map;

public class TestSecurityConfig
{
    @Test
    public void testDefaults()
    {
        ConfigAssertions.assertRecordedDefaults(ConfigAssertions.recordDefaults(AuthConfig.class)
                        .setAuthSchemes(null)
                        .setKrb5Conf(null)
                        .setServiceName(null)
        );
    }

    @Test
    public void testExplicitPropertyMappings()
    {
        Map<String, String> properties = new ImmutableMap.Builder<String, String>()
                .put("http-security.server.https.authentication.enabled-schemes", "negotiate")
                .put("http-security.server.https.authentication.negotiate.krb5conf", "/etc/krb5.conf")
                .put("http-security.server.https.authentication.negotiate.service-name", "airlift")
                .build();

        AuthConfig expected = new AuthConfig()
                .setAuthSchemes("negotiate")
                .setKrb5Conf("/etc/krb5.conf")
                .setServiceName("airlift");

        ConfigAssertions.assertFullMapping(properties, expected);
    }
}
