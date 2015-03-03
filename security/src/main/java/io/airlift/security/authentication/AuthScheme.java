package io.airlift.security.authentication;

public enum AuthScheme
{
    NEGOTIATE("negotiate");

    private final String value;

    private AuthScheme(final String value)
    {
        this.value = value;
    }

    public static AuthScheme fromString(String value)
    {
        for (AuthScheme scheme : AuthScheme.values()) {
            if (scheme.value.equals(value)) {
                return scheme;
            }
        }

        throw new Error("Invalid value " + value +
                " for " + AuthScheme.class.getSimpleName());
    }

    @Override
    public String toString()
    {
        return value;
    }
}
