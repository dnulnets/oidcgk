package eu.stenlund.oidc.client;

import java.util.ArrayList;

/**
 * The response from the well known URL for the OIDC metadata. It does not containe everything, just
 * the things required for this application.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public class ProviderConfiguration {
    public String issuer;
    public String authorization_endpoint;
    public String token_endpoint;
    public String jwks_uri;
    public ArrayList<String> grant_types_supported;
    public ArrayList<String> response_types_supported;
    public ArrayList<String> scopes_supported;
}

