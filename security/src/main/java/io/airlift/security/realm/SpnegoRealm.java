package io.airlift.security.realm;

import io.airlift.log.Logger;
import io.airlift.security.authentication.server.SpnegoAuthenticationToken;
import io.airlift.security.exception.AuthenticationException;
import io.airlift.security.utils.KerberosUtil;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.eclipse.jetty.util.B64Code;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;

import java.net.UnknownHostException;

import static com.google.common.base.Preconditions.checkNotNull;

public class SpnegoRealm extends AuthenticatingRealm
{
    private final String krb5Conf;
    private final String serviceName;
    private final String realmName;
    private GSSContext gssContext;

    private static final Logger log = Logger.get(SpnegoRealm.class);

    public SpnegoRealm(String realmName, String serviceName, String krb5Conf)
    {
        checkNotNull(serviceName, "serviceName is null");
        checkNotNull(krb5Conf, "krb5Conf is null");
        checkNotNull(realmName, "realmName is null");
        this.krb5Conf = krb5Conf;
        this.serviceName = serviceName;
        this.realmName = realmName;
    }

    @Override
    public boolean supports(AuthenticationToken token)
    {
        if (token != null) {
            return token instanceof SpnegoAuthenticationToken;
        }
        return false;
    }

    @Override
    public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException
    {
        String encodedAuthToken = (String) token.getCredentials();
        byte[] authToken = B64Code.decode(encodedAuthToken);
        try {
            if (gssContext == null) {
                if (log.isDebugEnabled()) {
                    log.debug("gssContext is null");
                }
            }
            else {
                while (!gssContext.isEstablished()) {
                    authToken = gssContext.acceptSecContext(authToken, 0, authToken.length);
                }
                if (gssContext.isEstablished()) {
                    String clientName = gssContext.getSrcName().toString();
                    String role = clientName.substring(clientName.indexOf('@') + 1);

                    if (log.isDebugEnabled()) {
                        log.debug("Established a gss context");
                        log.debug("Client Principal is: " + gssContext.getSrcName());
                        log.debug("Server Principal is: " + gssContext.getTargName());
                        log.debug("Client Default Role: " + role);
                    }
                    KerberosPrincipal kerberosPrincipal = new KerberosPrincipal(clientName);
                    return new SimpleAuthenticationInfo(kerberosPrincipal, authToken, getRealmName());
                }
            }
        }
        catch (GSSException e) {
            log.warn(String.valueOf(e));
        }
        return null;
    }

    @Override
    protected void onInit()
    {
        try {
            final String servicePrincipal = KerberosUtil.getServicePrincipal(serviceName, null);
            Subject serviceSubject = KerberosUtil.getSubject(serviceName, krb5Conf, false);
            gssContext = KerberosUtil.getGssContext(serviceSubject, servicePrincipal, false);
        }
        catch (UnknownHostException | LoginException e) {
            throw new AuthenticationException(e);
        }
    }

    public String getRealmName() { return realmName; }

    public String getServiceName() { return serviceName; }

    public String getKrb5Conf() { return krb5Conf; }
}
