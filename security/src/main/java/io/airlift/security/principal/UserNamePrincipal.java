package io.airlift.security.principal;

import java.security.Principal;

public class UserNamePrincipal implements Principal
{
    private final String userName;

    public UserNamePrincipal(String userName)
    {
        this.userName = userName;
    }

    public String getName()
    {
        return userName;
    }

    @Override
    public String toString()
    {
        return userName;
    }
}
