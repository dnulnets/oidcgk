package eu.stenlund.oidc;

import jakarta.ws.rs.GET;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriInfo;

import org.jboss.resteasy.reactive.ClientWebApplicationException;
import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.RestResponse.ResponseBuilder;
import org.jboss.resteasy.reactive.RestResponse.StatusCode;

import eu.stenlund.Application;
import eu.stenlund.Configuration;
import eu.stenlund.Error;
import eu.stenlund.oidc.client.TokenService;
import eu.stenlund.oidc.client.Tokens;
import eu.stenlund.session.storage.IStorage;
import eu.stenlund.session.storage.Session;
import eu.stenlund.session.storage.SessionKey;
import eu.stenlund.session.SessionHelper;
import io.quarkus.arc.log.LoggerName;
import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;

import java.net.URI;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;
import org.jboss.logmanager.MDC;


/**
 * Handles all incoming requests that have to do with logging in a user and the callback for a
 * successfull login.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
@Path("/oidc")
public class Resource {

    /** Logger */
    @Inject Logger log;
    @LoggerName("AUDIT") Logger audit;

    /* The root application */
    @Inject Application appl;

    /* The session helper */
    @Inject SessionHelper sessionHelper;

    /* The configuration */
    @Inject Configuration config;

    /**
     * Session storage, for now it is only the BrowserSessionStorage but we will increase it with more
     * type os storage solutions.
     */
    @Inject Instance<IStorage> storage;

    /* The OIDC internal client */
    private TokenService tokenService = null;

    /**
     * Initializes the bean.
     */
    @PostConstruct
    void init()
    {
        /* Create the token service from the well known configuration */
        log.info ("Initializing");
        log.info ("Creating the token service client");
        tokenService = QuarkusRestClientBuilder.newBuilder()
            .baseUri(config.getTokenEndpoint())
            .build(TokenService.class);
    }

    /**
     * Refreshes the id and authroization token using the refresh token.
     * 
     * @param s The session that needs refreshing
     * @return A refreshed session or null if it failed
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

        log.info ("No session to refresh");
        return null;
    }

    /**
     * Handles the login to the OIDC-provider.
     * 
     * @param httpHeaders The HTTP headers
     * @param uriInfo The URI information for the request
     * @param redirect_uri The redirect URI that is used after successful login
     * @return A redirect response to either login or to the application
     */
    @Path("login")
    @GET
    public RestResponse<Object> login(HttpHeaders httpHeaders, @Context UriInfo uriInfo, 
        @QueryParam(value = "redirect_uri") String redirect_uri) 
    {
        ResponseBuilder<Object> rr = null;

        /* Loggable information, get some trace id */
        MDC.put("RequestID", SessionHelper.generateRandomUUID());

        /* Get our storage */
        storage.get().setCookies(httpHeaders.getCookies().values());

        /* Did we get a session cookie */
        Session s = storage.get().getSession();
        if (s!=null) {

            /* Loggable information */
            MDC.put("SessionKey", s.id);

            /* Is the session valid? */
            if (s.access_token != null) {

                if (sessionHelper.verifyToken(s.access_token, s.subject)==null) {

                    audit.infof ("Login subject=%s", s.subject);

                    rr = ResponseBuilder.ok().header("Authorization", "Bearer "+s.access_token);

                    /* Yes we have a valid session, redirect us to the application url */
                    if (s.redirect_uri == null) {
                        s.redirect_uri = config.getApplicationURL();
                        storage.get().updateSession(s);
                    }

                    rr = ResponseBuilder.create(StatusCode.FOUND).location(URI.create(s.redirect_uri));

                } else {

                    log.info ("We were unable to verify the access token for the session");
                    log.info ("Refreshing token");

                    Session ns = refreshSession(s); 
                    if (ns != null) {

                        if (sessionHelper.verifyToken(ns.access_token, ns.subject) != null) {

                            /* Check redirect uri */
                            if (ns.redirect_uri == null)
                                ns.redirect_uri = config.getApplicationURL();

                            /* Update the stored session */                                                        
                            storage.get().updateSession(ns);
                            audit.infof ("Login initiated for subject=%s", s.subject);
                            rr = ResponseBuilder.create(StatusCode.FOUND).location(URI.create(s.redirect_uri));

                        } else {

                            log.info ("Refreshed token failed token verification");
                            storage.get().removeSession();
                            audit.errorf ("Login failed to initiate for subject=%s", s.subject);
                            rr = ResponseBuilder.create (StatusCode.FORBIDDEN).
                                entity (new Error ("Refreshed token failed token verification"));                            
                        }


                    } else {

                        storage.get().removeSession();
                        log.info ("Unable to refresh the access token");
                        audit.errorf ("Login failed to initiate for subject=%s", s.subject);
                        rr = ResponseBuilder.create (StatusCode.FORBIDDEN).entity (new Error ("Unable to refresh access token"));

                    }

                }

            } else {

                /* Not a valid session */
                log.info ("No access token present in the session information");
                storage.get().removeSession();
                audit.errorf ("Login failed to initiate");
                rr = ResponseBuilder.create(StatusCode.FORBIDDEN)
                    .entity (new Error ("No access token present in the session information"));
            }

        } else {

            /* Create the session */
            Session ns = new Session();
            ns.redirect_uri = redirect_uri!=null?redirect_uri:config.getApplicationURL();

            /* Store the session */
            storage.get().addSession(ns);
            MDC.put("SessionKey", ns.id);

            /* Create the redirect to the login page */
            SessionKey key = storage.get().getSessionKey();
            if (key != null) {
                audit.infof ("Login initiated for unknown subject");
                rr = ResponseBuilder.create(StatusCode.FOUND).location (config.buildRedirectToLogin (key.id));
            } else {
                log.warn("Not able to generate key, unable to initiate login sequence");
                audit.errorf ("Login failed to initiate for unknown subject");
                rr = ResponseBuilder.create(StatusCode.INTERNAL_SERVER_ERROR)
                    .entity (new Error ("Unable to initiate login sequence, unable to generate key"));
            }
        }

        /* Add some default headers */
        rr.header("cache-control", "no-store, must-revalidate, max-age=0").
            header("content-security-policy", "frame-src 'self'; frame-ancestors 'self'; object-src 'none';");

        /* Add the cookies, if any */
        for (Cookie nc : storage.get().getCookies()) {
            rr.cookie((NewCookie)nc);
        }

        return rr.build();
    }

    /**
     * The callback after a successfull login. It exchange the code to a set of JWT tokens.
     * 
     * @param httpHeaders The HTTP headers
     * @param uriInfo The URI information
     * @param state The returned state from the login redirection, it must be the key of the session.
     * @param code The authroization code from the OIDC-provider
     * @param session_state The OIDC-providers state
     * @return
     */
    @Path("callback")
    @GET
    public RestResponse<Object> callback(HttpHeaders httpHeaders, @Context UriInfo uriInfo, 
        @QueryParam(value="state") String state ,
        @QueryParam(value="code") String code,
        @QueryParam(value="session_state") String session_state) 
    {
        ResponseBuilder<Object> rr = null;

        /* Loggable information */
        MDC.put("RequestID", SessionHelper.generateRandomUUID());

        /* Validate our request */
        if (state ==null) {
            log.info ("Missing state parameter");
            audit.error("Login failed");
            rr = ResponseBuilder.create(StatusCode.BAD_REQUEST).entity(new Error ("Malformed request"));
            return rr.build();
        }

        if (code == null) {
            log.infof ("Missing code parameter, state=%s", state);
            audit.error("Login failed");
            rr = ResponseBuilder.create(StatusCode.BAD_REQUEST).entity(new Error ("Malformed request"));
            return rr.build();  
        }

        /* get hold of the session */
        storage.get().setCookies(httpHeaders.getCookies().values());
        Session s = storage.get().getSession();
        if (s != null) {

            MDC.put("SessionKey", s.id);

            /* Check state */
            if (s.id.compareTo(state) == 0) {

                /* Get the refresh and accesstokens */
                try {

                    /* Exchange the code to a token */
                    Tokens t = tokenService.token(config.getOIDCClient(), 
                        config.getCallbackURL().toString(), 
                        "authorization_code", 
                        code, 
                        config.getOIDCSecret(), 
                        null);

                    /* Validate the response */
                    if (t.token_type.compareTo("Bearer")!=0) {

                        /* We only support Bearer */
                        log.warnf ("We only support Bearer token type, not %s", t.token_type);
                        audit.error("Login failed");
                        storage.get().removeSession();
                        s = null;
                        rr = ResponseBuilder.create(StatusCode.NOT_IMPLEMENTED).entity(new Error ("Unsupported token type "+t.token_type));

                    } else {

                        JsonWebToken jwt = sessionHelper.verifyToken(t.access_token, null);
                        if (jwt != null) {

                            /* Audit log it */
                            audit.infof ("Login succeeded, subject=%s", jwt.getSubject());

                            /* Update the session */
                            s.access_token = t.access_token;
                            s.refresh_token = t.refresh_token.orElse(null);
                            s.id_token = t.id_token;
                            s.subject = jwt.getSubject();

                            /* Redirect us to the application */
                            if (s.redirect_uri == null)
                                s.redirect_uri = config.getApplicationURL();
                            rr = ResponseBuilder.create (StatusCode.FOUND).location (URI.create(s.redirect_uri));

                            /* Update the session */
                            storage.get().updateSession(s);

                        } else {

                            storage.get().removeSession();
                            audit.error ("Login failed, unable to verify access token");
                            log.info ("Unable to verify the access token");
                            rr = ResponseBuilder.create (StatusCode.FORBIDDEN).entity (new Error ("Unable to verify access token"));

                        }

                    }
                    
                } catch (ClientWebApplicationException cwe) {

                    /* Callback without a valid session */
                    log.info ("Unable to exchange the code for the access token");
                    log.info (cwe.getMessage());
                    audit.errorf ("Login failed, code exchange failed, state=%s", state);
                    storage.get().removeSession();
                    s = null;
                    rr = ResponseBuilder.create (StatusCode.FORBIDDEN).entity (new Error ("Unable to get access token"));

                }

            } else {

                log.infof ("State do not align with session key, state=%s", state);
                audit.errorf ("Login failed, state do not align with session key, state=%s", state);
                storage.get().removeSession();
                s = null;
                rr = ResponseBuilder.create (StatusCode.FORBIDDEN).entity (new Error ("State and session do not match"));
            }

        } else {

            /* Callback without a valid session */
            log.infof ("No session found, state=%s", state);
            audit.error ("Callback with no session");
            storage.get().removeSession();
            rr = ResponseBuilder.create (StatusCode.NOT_FOUND).entity (new Error ("Session not found"));

        }

        /* Add some default headers */
        rr.header("cache-control", "no-store, must-revalidate, max-age=0").
            header("content-security-policy", "frame-src 'self'; frame-ancestors 'self'; object-src 'none';");

        /* Add the cookies, if any */
        for (Cookie nc : storage.get().getCookies()) {
            rr.cookie((NewCookie)nc);
        }

        return rr.build();
    }

}