package io.airlift.security.realm;

import com.google.common.base.Throwables;
import io.airlift.log.Logger;
import io.airlift.security.authentication.SpnegoAuthenticationToken;
import io.airlift.security.utils.KerberosUtil;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.eclipse.jetty.util.B64Code;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.net.UnknownHostException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;

public class SpnegoRealm extends AuthenticatingRealm
{
    private final String serviceName;
    private final String krb5Conf;
    private final String realmName;
    private GSSManager gssManager;

    private static final Logger log = Logger.get(SpnegoRealm.class);

    public SpnegoRealm(String realmName, String serviceName, String krb5Conf)
    {
        this.realmName = realmName;
        this.serviceName = serviceName;
        this.krb5Conf = krb5Conf;
    }

    private static class KerberosConfiguration extends Configuration
    {
        private final String principal;
        private final String krb5Conf;

        public KerberosConfiguration(String serviceName, String krb5Config)
                throws UnknownHostException
        {
            this.principal = KerberosUtil.getServicePrincipal(serviceName, null);
            this.krb5Conf = krb5Config;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name)
        {
            System.setProperty("java.security.krb5.conf", krb5Conf);

            Map<String, String> options = new HashMap<String, String>();
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("renewTGT", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "false");
            options.put("useTicketCache", "true");
            if (log.isDebugEnabled()) {
                options.put("debug", "true");
            }

            return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(),
                            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                            options)};
        }
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
        String encodedAuthToken = (String)token.getCredentials();

        byte[] authToken = B64Code.decode(encodedAuthToken);

        try {
            Oid krb5Oid = new Oid("1.3.6.1.5.5.2");
            String krbPrincipal = KerberosUtil.getServicePrincipal(serviceName, null);
            GSSName gssName = gssManager.createName(krbPrincipal, GSSName.NT_HOSTBASED_SERVICE);
            GSSCredential serverCreds = gssManager.createCredential(
                    gssName,
                    GSSCredential.INDEFINITE_LIFETIME,
                    krb5Oid,GSSCredential.ACCEPT_ONLY);
            GSSContext gContext = gssManager.createContext(serverCreds);

            if (gContext == null) {
                if (log.isDebugEnabled()) {
                    log.debug("SpnegoUserRealm: failed to establish GSSContext");
                }
            } else {
                while (!gContext.isEstablished()) {
                    authToken = gContext.acceptSecContext(authToken, 0, authToken.length);
                }
                if (gContext.isEstablished()) {
                    String clientName = gContext.getSrcName().toString();
                    String role = clientName.substring(clientName.indexOf('@') + 1);

                    if (log.isDebugEnabled()) {
                        log.debug("SpnegoUserRealm: established a security context");
                        log.debug("Client Principal is: " + gContext.getSrcName());
                        log.debug("Server Principal is: " + gContext.getTargName());
                        log.debug("Client Default Role: " + role);
                    }
                    KerberosPrincipal kerberosPrincipal = new KerberosPrincipal(clientName);
                    return new SimpleAuthenticationInfo(kerberosPrincipal, authToken, getRealmName());
                }
            }
        } catch (UnknownHostException | GSSException gsse) {
            log.warn(String.valueOf(gsse));
        }
        return null;
    }

    @Override
    protected void onInit()
    {
        try {
            checkNotNull(serviceName, "serviceName is null");
            checkNotNull(krb5Conf, "krb5Conf is null");

            KerberosConfiguration kerberosConfiguration = new KerberosConfiguration(serviceName, krb5Conf);
            LoginContext loginContext = new LoginContext("GSSServer", null, null, kerberosConfiguration);
            loginContext.login();
            Subject subject = loginContext.getSubject();
            gssManager = Subject.doAs(subject, new PrivilegedExceptionAction<GSSManager>() {
                public GSSManager run() throws Exception {
                    return GSSManager.getInstance();
                }
            });
            log.info("Initialized, serviceName [{}] from krb5Conf [{}]", serviceName, krb5Conf);
        } catch (UnknownHostException | PrivilegedActionException | LoginException e) {
            throw Throwables.propagate(e);
        }
    }

    public String getRealmName() { return realmName; }

    public String getServiceName() { return serviceName; }

    public String getKrb5Conf() { return krb5Conf; }
}
