package eu.stenlund;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import eu.stenlund.oidc.client.ProviderConfiguration;
import eu.stenlund.oidc.client.ProviderConfigurationService;
import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.UriBuilder;

/**
 * A helper class for all configuration in the application and also for the infomation stored at the
 * well known endpoint for OpenID Connect.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
@Singleton
public class Configuration {

    /* Logger */
    private static final Logger log = Logger.getLogger(Configuration.class);

    /* Get the cookie configuration */
    @ConfigProperty(name = "oidcgk.cookie.name", defaultValue = "oidcgk") String cName;
    @ConfigProperty(name = "oidcgk.cookie.domain") String cDomain;
    @ConfigProperty(name = "oidcgk.cookie.path", defaultValue = "/") String cPath;
    @ConfigProperty(name = "oidcgk.cookie.maxage", defaultValue = "10800") int cMaxAge;

    /* OIDC Provider configuration */
    @ConfigProperty(name = "oidcgk.oidc.url") String oidcURL;
    @ConfigProperty(name = "oidcgk.oidc.realm") String oidcRealm;
    @ConfigProperty(name = "oidcgk.oidc.client") String oidcClient;
    @ConfigProperty(name = "oidcgk.oidc.secret") String oidcSecret;
    @ConfigProperty(name = "oidcgk.oidc.scope") String oidcScope;
    @ConfigProperty(name = "oidcgk.oidc.audience") String oidcAudience;
    @ConfigProperty(name = "oidcgk.oidc.pkce", defaultValue = "false") Boolean oidcPKCE;

    /* The base URL for the application root */
    @ConfigProperty(name = "oidcgk.base.url") String baseURL;

    /* The applications context used as an AAD during encryption when we are using browser based session storage */
    @ConfigProperty(name = "oidcgk.base.context", defaultValue = "OpenID Connect Gate Keeper Version 1.0") String context;

    /* Time to live in seconds for a session in storage */
    @ConfigProperty(name = "oidcgk.base.storage.TTL", defaultValue = "1800") int storageTTL;

    /* The url for the application to redirect to after login */
    @ConfigProperty(name = "oidcgk.application.url") String applicationURL;

    /*  The provider configuration */
    private ProviderConfiguration providerConfig;

    /* Initialize the application */
    @PostConstruct 
    void init() {
        log.info ("Build the configuration for " + oidcRealm);

        /* Create the discovery service */
        ProviderConfigurationService providerConfigurationService = QuarkusRestClientBuilder.newBuilder()
            .baseUri(getOIDCBaseURL())
            .build(ProviderConfigurationService.class);

        /* Get hold of the well known configuration */
        providerConfig = providerConfigurationService.get();
        log.info ("issuer = " + providerConfig.issuer);
        log.info ("authorization endpoint = " + providerConfig.authorization_endpoint);
        log.info ("token endpoint = " + providerConfig.token_endpoint);
        log.info ("jwks URI = " + providerConfig.jwks_uri);
        log.info ("end_session_endpoint = " + providerConfig.end_session_endpoint);
    }

    public String getAudience() {
        return oidcAudience;
    }

    public Set<String> getAudienceSet() {
        Set<String> ss = new HashSet<String>(Arrays.asList(oidcAudience.trim().split("\\s+")));
        return ss;
    }

    public String getContext() {
        return context;
    }

    public int getCookieMaxAge()
    {
        return cMaxAge;
    }

    public String getCookiePath()
    {
        return cPath;
    }

    public String getCookieName() {
        return cName;
    }

    public Boolean getOIDCPKCE()
    {
        return oidcPKCE;
    }

    public String getCookieDomain () {
        return cDomain;
    }

    public String getOIDCURL() {
        return oidcURL;
    }

    public String getOIDCRealm() {
        return oidcRealm;
    }

    public String getOIDCClient() {
        return oidcClient;
    }

    public String getOIDCSecret() {
        return oidcSecret;
    }

    public String getBaseURL() {
        return baseURL;
    }

    public String getApplicationURL() {
        return applicationURL;
    }

    public URI getTokenEndpoint() {
        return URI.create(providerConfig.token_endpoint);
    }

    public URI getEndSessionEndpoint() {
        return URI.create(providerConfig.end_session_endpoint);
    }

    public URI getJWKSEndpoint() {
        return URI.create (providerConfig.jwks_uri);
    }

    public String getIssuer() {
        return providerConfig.issuer;
    }

    /**
     * Builds an URI for the redirection to the login service at the OIDC provider.
     * 
     * @param state Our state
     * @return A URI to the login service
     */
    public URI buildRedirectToLogin(String state, String code_challenge)
    {

        UriBuilder urib = UriBuilder.fromUri(providerConfig.authorization_endpoint).
            queryParam("client_id","{client}").
            queryParam("response_type", "code");
            
        if (code_challenge != null)
            urib = urib.queryParam("code_challenge", code_challenge).
                queryParam("code_challenge_method", "S256");

        URI uri = urib.
            queryParam("state", "{state}").
            queryParam("scope", oidcScope!=null?"openid " + oidcScope:"oidc").
            queryParam("redirect_uri", "{redirect}").
            build(oidcClient, state, getCallbackURL().toString());

        return uri;
    }

    /**
     * Builds an URI for the callback to the gatekeeper after succesfull login.
     * 
     * @return A URI to the gatekeeper.
     */
    public URI getCallbackURL()
    {
        URI redirect = UriBuilder.fromUri(baseURL).
            path("oidc/callback").build();
        return redirect;
    }
    
    /**
     * Builds a base URI to the realm.
     * 
     * @return A base URI for the realm.
     */
    public URI getOIDCBaseURL ()
    {
        URI uri = UriBuilder.fromUri(oidcURL).
            path("realms/{realm}").
            build(oidcRealm);

        return uri;
    }

    /**
     * Returns with the TTL for a stored session.
     * @return The TTL in seconds
     */
    public long getTTL() {
        return storageTTL;
    }
}
