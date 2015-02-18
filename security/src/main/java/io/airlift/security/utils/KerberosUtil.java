package io.airlift.security.utils;

import io.airlift.log.Logger;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * From https://issues.apache.org/jira/browse/SHIRO-499
 */
public class KerberosUtil
{
    private static final Logger log = Logger.get(KerberosUtil.class);

    /* Return the Kerberos login module name */
    public static String getKrb5LoginModuleName()
    {
        return System.getProperty("java.vendor").contains("IBM")
                ? "com.ibm.security.auth.module.Krb5LoginModule"
                : "com.sun.security.auth.module.Krb5LoginModule";
    }

    public static Oid getOidInstance(String oidName)
            throws ClassNotFoundException, GSSException, NoSuchFieldException,
            IllegalAccessException
    {
        Class<?> oidClass;
        if (System.getProperty("java.vendor").contains("IBM")) {
            oidClass = Class.forName("com.ibm.security.jgss.GSSUtil");
        } else {
            oidClass = Class.forName("sun.security.jgss.GSSUtil");
        }
        Field oidField = oidClass.getDeclaredField(oidName);
        return (Oid) oidField.get(oidClass);
    }

    public static String getDefaultRealm()
            throws ClassNotFoundException, NoSuchMethodException,
            IllegalArgumentException, IllegalAccessException,
            InvocationTargetException
    {
        Object kerbConf;
        Class<?> classRef;
        Method getInstanceMethod;
        Method getDefaultRealmMethod;
        if (System.getProperty("java.vendor").contains("IBM")) {
            classRef = Class.forName("com.ibm.security.krb5.internal.Config");
        } else {
            classRef = Class.forName("sun.security.krb5.Config");
        }
        getInstanceMethod = classRef.getMethod("getInstance", new Class[0]);
        kerbConf = getInstanceMethod.invoke(classRef, new Object[0]);
        getDefaultRealmMethod = classRef.getDeclaredMethod(
                "getDefaultRealm",
                new Class[0]);
        return (String) getDefaultRealmMethod.invoke(kerbConf, new Object[0]);
    }

    /**
     * Create Kerberos principal for a given service and hostname. It converts
     * hostname to lower case. If hostname is null or "0.0.0.0", it uses
     * dynamically looked-up fqdn of the current host instead.
     *
     * @param service Service for which you want to generate the principal.
     * @param hostname Fully-qualified domain name.
     * @return Converted Kerberos principal name.
     * @throws UnknownHostException If no IP address for the local host could be found.
     */
    public static final String getServicePrincipal(String service, String hostname)
            throws UnknownHostException
    {
        String fqdn = hostname;
        if (null == fqdn || fqdn.equals("") || fqdn.equals("0.0.0.0")) {
            fqdn = InetAddress.getLocalHost().getCanonicalHostName();;
        }
        return service + "/" + fqdn.toLowerCase(Locale.US);
    }
}
