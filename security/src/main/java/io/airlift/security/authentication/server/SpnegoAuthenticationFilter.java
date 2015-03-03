package io.airlift.security.authentication.server;

import com.google.common.base.Strings;
import io.airlift.log.Logger;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.eclipse.jetty.http.HttpHeader;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SpnegoAuthenticationFilter extends AuthenticatingFilter
{
    private static final Logger log = Logger.get(SpnegoAuthenticationFilter.class);
    private static final String authScheme = HttpHeader.NEGOTIATE.asString();

    public String getAuthScheme() { return authScheme; }

    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception
    {
        boolean loggedIn = false;
        if (isLoginAttempt(request, response)) {
            loggedIn = executeLogin(request, response);
        }
        if (!loggedIn) {
            sendChallenge(request, response);
        }
        return loggedIn;
    }

    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response)
    {
        String authzHeader = getAuthzHeader(request);
        return authzHeader != null && authzHeader.startsWith(authScheme);
    }

    protected String getAuthzHeader(ServletRequest request)
    {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader(HttpHeader.AUTHORIZATION.toString());
    }

    protected boolean sendChallenge(ServletRequest request, ServletResponse response)
    {
        if (log.isDebugEnabled()) {
            log.debug("Authentication required: sending 401 Authentication challenge response.");
        }
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.setHeader(HttpHeader.WWW_AUTHENTICATE.asString(), authScheme);
        return false;
    }

    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response)
    {
        String authorizationHeader = getAuthzHeader(request);
        if (Strings.isNullOrEmpty(authorizationHeader)) {
            return null;
        }
        if (log.isDebugEnabled()) {
            log.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
        }
        String spnegoToken = authorizationHeader.substring(10);
        return new SpnegoAuthenticationToken(null, spnegoToken);
    }

    @Override
    protected final boolean isLoginRequest(ServletRequest request, ServletResponse response)
    {
        return this.isLoginAttempt(request, response);
    }
}
