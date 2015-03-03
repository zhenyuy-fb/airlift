package io.airlift.security.authentication.client;

import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import io.airlift.log.Logger;
import io.airlift.security.authentication.AuthScheme;
import io.airlift.security.config.ClientSecurityConfig;
import io.airlift.security.utils.KerberosUtil;
import org.eclipse.jetty.client.api.Authentication;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.util.Attributes;
import org.eclipse.jetty.util.B64Code;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import java.net.URI;
import java.net.UnknownHostException;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class SpnegoAuthentication
        implements Authentication
{
    private GSSContext gssContext;

    private static final String NEGOTIATE = HttpHeader.NEGOTIATE.asString();
    private static final Logger log = Logger.get(SpnegoAuthentication.class);

    public SpnegoAuthentication(ClientSecurityConfig clientSecurityConfig, URI serviceUri)
    {
        checkNotNull(clientSecurityConfig, "securityClientConfig is null");
        checkNotNull(serviceUri, "serviceUri is null");
        checkArgument(!Strings.isNullOrEmpty(clientSecurityConfig.getKrb5Conf()), "krb5Conf is null or empty");
        checkArgument(!Strings.isNullOrEmpty(clientSecurityConfig.getServiceName()), "serviceName is null or empty");
        try {
            init(clientSecurityConfig, serviceUri);
        } //TODO propagate exceptions properly
        catch (UnknownHostException | LoginException e) {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public Result authenticate(Request request, ContentResponse response, HeaderInfo headerInfo, Attributes context)
    {
        byte[] token = new byte[0];
        try {
            if (!gssContext.isEstablished()) {
                byte[] peerToken = headerInfo.getHeader().getBytes();
                token = gssContext.initSecContext(peerToken, 0, peerToken.length);
            }
            if (gssContext.isEstablished()) {
                log.debug("Successfully established GSSContext with source name: %s and target name: %s",
                        gssContext.getSrcName(),
                        gssContext.getTargName());
                String spnegoToken = NEGOTIATE + " " + String.valueOf(B64Code.encode(token));
                return new SpnegoResult(headerInfo.getHeader(), request.getURI(), spnegoToken);
            }
            else {
                log.warn("Failed to establish GSSContext for request %s!", request.getURI());
                return null;
            }
        } //TODO propagate exceptions properly
        catch (GSSException e) {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public boolean matches(String type, URI uri, String realm)
    {
        return AuthScheme.NEGOTIATE.toString().equalsIgnoreCase(type);
    }

    private void init(ClientSecurityConfig clientSecurityConfig, URI serviceHost) throws UnknownHostException, LoginException

    {
        String krb5Conf = clientSecurityConfig.getKrb5Conf();
        String serviceName = clientSecurityConfig.getServiceName();
        String serviceHostName = serviceHost.getHost();
        String servicePrincipal = KerberosUtil.getServicePrincipal(serviceName, serviceHostName);
        Subject clientSubject = KerberosUtil.getSubject(null, krb5Conf, true);
        gssContext = KerberosUtil.getGssContext(clientSubject, servicePrincipal, true);
    }

    private static class SpnegoResult
            implements Result
    {
        private final HttpHeader header;
        private final URI uri;
        private final String value;

        public SpnegoResult(HttpHeader header, URI uri, String value)
        {
            this.header = header;
            this.uri = uri;
            this.value = value;
        }

        @Override
        public URI getURI()
        {
            return uri;
        }

        @Override
        public void apply(Request request)
        {
            request.header(header, value);
        }
    }
}
