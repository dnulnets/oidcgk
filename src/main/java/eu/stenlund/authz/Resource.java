package eu.stenlund.authz;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.RuntimeDelegate;

import org.jboss.resteasy.reactive.ClientWebApplicationException;
import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.RestResponse.ResponseBuilder;
import org.jboss.resteasy.reactive.RestResponse.StatusCode;

import eu.stenlund.Application;
import eu.stenlund.Configuration;
import eu.stenlund.oidc.client.TokenService;
import eu.stenlund.oidc.client.Tokens;
import eu.stenlund.session.SessionHelper;
import eu.stenlund.session.storage.BrowserSessionStorage;
import eu.stenlund.session.storage.IStorage;
import eu.stenlund.session.storage.Session;
import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;

import java.util.Collection;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;
import org.jboss.logmanager.MDC;

/**
 * Handles all incoming requests that are supposed to be authorized. Initiated by the istio
 * AuthroizationPolicy.
 */
@Path("/")
public class Resource {

    /** Logger */
    private static final Logger log = Logger.getLogger(Resource.class);

    /* Get the application */
    @Inject Application appl;

    /* Session helper */
    @Inject SessionHelper sessionHelper;

    /* Get the configuration */
    @Inject Configuration config;
    
    /* Get the parser */
    @Inject JWTParser jwtParser;

    /* The session storage */
    @Inject Instance<IStorage> storage;

    /* Get the OIDC provider internal client */
    private TokenService tokenService = null;

    /**
     * Initializes the bean
     */
    @PostConstruct
    void init()
    {
        /* Create the token service from the well known configuration */
        tokenService = QuarkusRestClientBuilder.newBuilder()
            .baseUri(config.getTokenEndpoint())
            .build(TokenService.class);
    }

    /**
     * Refreshes a session using the refresh token and returns with the new session.
     * 
     * @param s The current session that needs renewal.
     * @return A new renewed session or null if it failed.
     */
    private Session refreshSession (Session s)
    {
        /* Get the session */
        if (s!=null) {

            try {
                /* Refresh the tokens */
                Tokens t = tokenService.token(config.getOIDCClient(), 
                    null, 
                    "refresh_token", 
                    null, 
                    config.getOIDCSecret(), 
                    s.refresh_token);

                /* Update the session */
                s.access_token = t.access_token;
                s.refresh_token = t.refresh_token.orElse(null);
                s.id_token = t.id_token;
                return s;

            } catch (ClientWebApplicationException cwe) {

                /* Refresh without a valid session */
                log.info ("Unable to refresh token");
                log.info (cwe.getMessage());
                return null;

            }

        }

        log.info ("No session provided");
        return null;
    }

    /**
     * Generates the cookie header value and removes all oidcgk cookies. They do not need to be sent upstream.
     * 
     * @param cookies A collection of cookies
     * @return The cookie header value
     */
    private String generateCleanedCookieHeader (Collection<Cookie> cookies)
    {
        final String cn = config.getCookieName() + "-";
        final String ncn = "n" + config.getCookieName();
        String ch = cookies.stream()
            .filter(c -> !(c.getName().compareTo(ncn)==0 || c.getName().startsWith(cn)))
            .map(c -> RuntimeDelegate.getInstance().createHeaderDelegate(Cookie.class).toString(c))
            .reduce("", (s,e) -> s + (s.length()==0?"":";") + e);
        
        return ch;
    } 

    /**
     * Perform the authorization check given the path and method. It will generate the authorization
     * header based on the session data and istio will send it upstream. It will also generate the
     * set-cookie header for changed session data that istio will send downstream back to the client.
     * 
     * @param path The path of the request
     * @param method The methods of the request
     * @param cookies The cookie header value to be sent upstream
     * @return
     */
    private RestResponse<Object> performAuthzCheck(String path, String method, String cookies)
    {
        ResponseBuilder<Object> rr = null;

        /* Make sure we got a cookie */
        Session s = storage.get().getSession();
        if (s != null) {

            /* Set the session key */
            MDC.put("SessionKey", s.id);

            /* Is the session valid? */
            if (s.access_token != null) {

                try {
                    JsonWebToken jwt = jwtParser.parse (s.access_token);
                    rr = ResponseBuilder.ok().header("Authorization", "Bearer "+s.access_token);
                } catch (ParseException e) {

                    log.info ("The access token failed verification for the session");
                    log.info (e.getMessage());
                    log.info ("Trying to refresh it");
                    /* it failed to verify, try to refresh it */
                    Session ns = refreshSession(s);
                    if (ns != null) {

                        log.info ("Refreshed");
                        storage.get().updateSession(ns);
                        /* We are allowed so we need to propagate the token upstreams */
                        rr = ResponseBuilder.ok().header("Authorization", "Bearer "+s.access_token);

                    } else {

                        log.info ("Failed to refresh it, removing session");
                        storage.get().removeSession();
                        s =null;
                        rr = ResponseBuilder.create (StatusCode.FORBIDDEN).
                            entity (new Error ("Unable to refresh access token"));

                    }

                }

            } else {

                /* Not a valid session */
                log.info ("No access token present in the session");
                storage.get().removeSession();
                s = null;
                rr = ResponseBuilder.create (StatusCode.FORBIDDEN).
                    entity (new Error ("Missing access token"));
            }

        } else {

            /* No session, so we will deny this request */
            log.info ("No session found");
            storage.get().removeSession();
            rr = ResponseBuilder.create(StatusCode.FORBIDDEN, "No valid session");
        }

        /* Add some default headers */
        rr.header("cache-control", "no-store, must-revalidate, max-age=0").
            header("content-security-policy", "frame-src 'self'; frame-ancestors 'self'; object-src 'none';");

        /* Add any updated cookies, this is set-cookies to go back downstream */
        Collection<Cookie> st = storage.get().getCookies();
        for (Cookie nc : st) {
            rr.cookie((NewCookie)nc);
        }

        /* Remove oidcgk cookies that comes from downstream so they are not propagated upstream. Let the other
         * cookies through */
        rr.header ("Cookie", cookies);

        /* Build the response */
        return rr.build();
    }

    /* We always return 200 for OPTION */
    @Path("{:.+}")
    @OPTIONS
    public RestResponse<Object> optionsCheck(HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        MDC.put("RequestID", SessionHelper.generateRandomUUID());
        log.info ("Authorization check for URI = " + uriInfo.getPath() + " and scope = OPTIONS");
        return ResponseBuilder.ok().build();
    }

    /* GET => Scope = GET */
    @Path("{:.+}")
    @GET
    public RestResponse<Object> getCheck(HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        MDC.put("RequestID", SessionHelper.generateRandomUUID());
        log.info ("Authorization check for URI = " + uriInfo.getPath() + " and scope = GET");
        storage.get().setCookies(httpHeaders.getCookies().values());
        String ch = generateCleanedCookieHeader(httpHeaders.getCookies().values());
        return performAuthzCheck (uriInfo.getPath(), "GET", ch);
    }

    /* HEAD is the same as GET, so Scope = GET */
    @Path("{:.+}")
    @HEAD
    public RestResponse<Object> headCheck(HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        MDC.put("RequestID", SessionHelper.generateRandomUUID());
        log.info ("Authorization check for URI = " + uriInfo.getPath() + " and scope = HEAD");
        storage.get().setCookies(httpHeaders.getCookies().values());
        String ch = generateCleanedCookieHeader(httpHeaders.getCookies().values());
        return performAuthzCheck (uriInfo.getPath(), "GET", ch);
    }

    /* POST => Scope POST */
    @Path("{:.+}")
    @POST
    public RestResponse<Object> postCheck(HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        MDC.put("RequestID", SessionHelper.generateRandomUUID());
        log.info ("Authorization check for URI = " + uriInfo.getPath() + " and scope = POST");
        storage.get().setCookies(httpHeaders.getCookies().values());
        String ch = generateCleanedCookieHeader(httpHeaders.getCookies().values());
        return performAuthzCheck (uriInfo.getPath(), "POST", ch);
    }

    /* PUT => Scope PUT */
    @Path("{:.+}")
    @PUT
    public RestResponse<Object> putCheck(HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        MDC.put("RequestID", SessionHelper.generateRandomUUID());
        log.info ("Authorization check for URI = " + uriInfo.getPath() + " and scope = PUT");
        storage.get().setCookies(httpHeaders.getCookies().values());
        String ch = generateCleanedCookieHeader(httpHeaders.getCookies().values());
        return performAuthzCheck (uriInfo.getPath(), "PUT", ch);
    }

    /* DELETE => Scope DELETE */
    @Path("{:.+}")
    @DELETE
    public RestResponse<Object> deleteCheck(HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        MDC.put("RequestID", SessionHelper.generateRandomUUID());
        log.info ("Authorization check for URI = " + uriInfo.getPath() + " and scope = DELETE");
        storage.get().setCookies(httpHeaders.getCookies().values());
        String ch = generateCleanedCookieHeader(httpHeaders.getCookies().values());
        return performAuthzCheck (uriInfo.getPath(), "DELETE",ch);
    }

    /* PATCH => Scope PATCH */
    @Path("{:.+}")
    @PATCH
    public RestResponse<Object> patchCheck(HttpHeaders httpHeaders, @Context UriInfo uriInfo) {
        MDC.put("RequestID", SessionHelper.generateRandomUUID());
        log.info ("Authorization check for URI = " + uriInfo.getPath() + " and scope = PATCH");
        storage.get().setCookies(httpHeaders.getCookies().values());
        String ch = generateCleanedCookieHeader(httpHeaders.getCookies().values());
        return performAuthzCheck (uriInfo.getPath(), "PATCH", ch);
    }
}
