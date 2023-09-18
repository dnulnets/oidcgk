package eu.stenlund.oidc.client;

import java.util.Optional;

public class Tokens {

    public String issuer;
    public String access_token;
    public String token_type;
    public int expires_in;
    public Optional<String> scope;
    public Optional<String> refresh_token;
    public String id_token;
}
