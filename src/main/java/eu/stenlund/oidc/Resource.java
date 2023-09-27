package eu.stenlund.oidc;

import jakarta.ws.rs.GET;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
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
import eu.stenlund.oidc.client.EndSessionService;
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
    private EndSessionService endSessionService = null;

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

        endSessionService = QuarkusRestClientBuilder.newBuilder()
            .baseUri(config.getEndSessionEndpoint())
            .build(EndSessionService.class);            
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
                    null,
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
     * Add some default headers and handle cookies.
     * 
     * @param rr The responsebuilder for the response
     * @return The response
     */
    private RestResponse<Object> finalizeResponse (ResponseBuilder<Object> rr)
    {
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
        Session s = storage.get().getSession();
        if (s!=null) {

            /* Loggable information */
            MDC.put("SessionKey", s.id);

            /* Is the session valid? */
            if (s.access_token != null) {

                /* Validate the token */
                if (sessionHelper.verifyToken(s.access_token, s.subject)==null) {

                    /* Log it */
                    audit.infof ("Login subject=%s, reason='Already logged in'", s.subject);
                    
                    /* Update storage */
                    if (s.redirect_uri == null) {
                        s.redirect_uri = config.getApplicationURL();
                        storage.get().updateSession(s);
                    }

                    /* Redirect us to the application */
                    rr = ResponseBuilder.create(StatusCode.FOUND)
                        .location(URI.create(s.redirect_uri));

                } else {

                    /* Log it */
                    log.info ("We were unable to verify the access token for the session");
                    log.info ("Refreshing token");

                    Session ns = refreshSession(s); 
                    if (ns != null) {

                        /* Verify the new token */
                        if (sessionHelper.verifyToken(ns.access_token, ns.subject) != null) {

                            /* Log it */
                            audit.infof ("Login subject=%s, reason='Already logged in'", s.subject);

                            /* Update the storage */
                            if (ns.redirect_uri == null)
                                ns.redirect_uri = config.getApplicationURL();
                            storage.get().updateSession(ns);

                            /* Redirect us to the application */
                            rr = ResponseBuilder.create(StatusCode.FOUND).location(URI.create(s.redirect_uri));

                        } else {

                            /* Log it */
                            log.info ("Refreshed token failed verification");
                            audit.errorf ("Login failed subject=%s, reason='Refreshed token failed verification'", s.subject);

                            /* Update storage */
                            storage.get().removeSession();
                            
                            /* Return with the error */
                            rr = ResponseBuilder.create (StatusCode.FORBIDDEN);
                        }


                    } else {

                        /* Log it */
                        log.info ("Unable to refresh the access token");
                        audit.errorf ("Login failed subject=%s, reason='Unable to refresh access token'", s.subject);

                        /* Update storage */
                        storage.get().removeSession();

                        /* Return with the error */
                        rr = ResponseBuilder.create (StatusCode.FORBIDDEN);

                    }

                }

            } else {

                /* Not a valid session */
                log.info ("No access token present in the session information");
                audit.errorf ("Login failed reason='No access token present in the session information'");

                /* Remove the session */
                storage.get().removeSession();
                
                /* Return with the error code */
                rr = ResponseBuilder.create(StatusCode.FORBIDDEN);
            }

        } else {

            /* Create the session */
            Session ns = new Session();
            ns.redirect_uri = redirect_uri!=null?redirect_uri:config.getApplicationURL();

            /* Create the PKCE verifier */
            ns.code_verifier = null;
            if (config.getOIDCPKCE())
                ns.code_verifier = sessionHelper.generateCodeVerifier();

            storage.get().addSession(ns);
            MDC.put("SessionKey", ns.id);

            /* Create the redirect to the login page */
            SessionKey key = storage.get().getSessionKey();
            if (key != null) {

                /* Log it */
                audit.infof ("Login initiated state=%s, reason='No previous session exists'", key.id);

                /* Create the PKCE code challenge */
                String code_challenge = null;
                if (config.getOIDCPKCE())
                    code_challenge = sessionHelper.generateCodeChallenge(ns.code_verifier);

                /* Redirect to login page */
                rr = ResponseBuilder.create(StatusCode.FOUND).location (config.buildRedirectToLogin (key.id, code_challenge));

            } else {

                /* Log it */
                log.warn("Not able to generate key, unable to initiate login sequence");
                audit.errorf ("Login failed state=%s, reason='Failed to generate session key'", ns.id);

                /* Remove the session */
                storage.get().removeSession();

                /* Internal server error */
                rr = ResponseBuilder.create(StatusCode.INTERNAL_SERVER_ERROR);
            }
        }

        return finalizeResponse(rr);
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
        @QueryParam(value="session_state") String session_state,
        @QueryParam(value="error") String error,
        @QueryParam(value="error_description") String error_description) 
    {
        ResponseBuilder<Object> rr = null;

        /* Keeping the request logging together */
        MDC.put("RequestID", SessionHelper.generateRandomUUID());

        /* Initialize the storage */
        storage.get().setCookies(httpHeaders.getCookies().values());
        Session s = storage.get().getSession();

        /* Are we in error ? */
        if (error !=null) {
            log.infof("Error %s in callback = %s", error, error_description!=null?error_description:"No description");
            audit.errorf("Login failed, %s", error);
            storage.get().removeSession();
            rr = ResponseBuilder.create (StatusCode.FORBIDDEN);
            return finalizeResponse(rr);
        }

        /* Validate our request */
        if (state == null) {
            log.info ("Missing state parameter");
            audit.error("Login failed");
            storage.get().removeSession();
            rr = ResponseBuilder.create(StatusCode.BAD_REQUEST);
            return finalizeResponse(rr);
        }

        if (code == null) {
            log.infof ("Missing code parameter, state=%s", state);
            audit.error("Login failed");
            storage.get().removeSession();
            rr = ResponseBuilder.create(StatusCode.BAD_REQUEST);
            return finalizeResponse(rr);
        }

        /* handle that the session exists */
        if (s != null) {

            /* Keep the session information together in the request */
            MDC.put("SessionKey", s.id);

            /* Check that the state is correct*/
            if (s.id.compareTo(state) == 0) {

                /* Get the refresh and accesstokens */
                try {

                    /* Exchange the code to the acccess, id and refresh tokens */
                    Tokens t = tokenService.token(config.getOIDCClient(), 
                        config.getCallbackURL().toString(), 
                        "authorization_code", 
                        code, 
                        config.getOIDCSecret(),
                        s.code_verifier,
                        null);

                    /* No need to hold on to the verifier any longer */
                    s.code_verifier = null;

                    /* Validate the response, we only support Bearer tokens */
                    if (t.token_type.compareTo("Bearer")!=0) {

                        /* Log it */
                        log.warnf ("We only support Bearer token type, not %s", t.token_type);
                        audit.error ("Login failed");

                        /* Update the session */
                        storage.get().removeSession();
                        s = null;

                        /* Return with the error */
                        rr = ResponseBuilder.create(StatusCode.NOT_IMPLEMENTED);

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
                            if (s.redirect_uri == null)
                                s.redirect_uri = config.getApplicationURL();
                            storage.get().updateSession(s);
                            
                            /* Redirect us to the application */
                            rr = ResponseBuilder.create (StatusCode.FOUND).location (URI.create(s.redirect_uri));

                        } else {

                            /* Log it */
                            audit.error ("Login failed, unable to verify access token");
                            log.info ("Unable to verify the access token");

                            /* Update the session */
                            storage.get().removeSession();

                            /* Reurn with the error */
                            rr = ResponseBuilder.create (StatusCode.FORBIDDEN);

                        }

                    }
                    
                } catch (ClientWebApplicationException cwe) {

                    /* Log it */
                    log.info ("Unable to exchange the code for the access token");
                    log.info (cwe.getMessage());
                    audit.errorf ("Login failed, code exchange failed, state=%s", state);

                    /* Update storage */
                    storage.get().removeSession();
                    s = null;

                    /* Return with the error, we could not exchange the code with the token */
                    rr = ResponseBuilder.create (StatusCode.FORBIDDEN);

                }

            } else {

                /* Log it */
                log.infof ("State do not align with session key, state=%s", state);
                audit.errorf ("Login failed, state do not align with session key, state=%s", state);

                /* Update the storage */
                storage.get().removeSession();
                s = null;

                /* return with the error */
                rr = ResponseBuilder.create (StatusCode.FORBIDDEN);
            }

        } else {

            /* Log it */
            log.infof ("No session found, state=%s", state);
            audit.error ("Callback with no session");


            /* Remove the session from storage */
            storage.get().removeSession();

            /* Return with the error, sessio is not found */
            rr = ResponseBuilder.create (StatusCode.NOT_FOUND);

        }

        return finalizeResponse(rr);
    }

    /**
     * Logs out the user and clears the session. Note that it does not do any logout on the OIDC Provider.
     * 
     * @param httpHeaders The HTTP headers
     * @param uriInfo The URI information
     * @return
     */
    @Path("logout")
    @GET
    @Produces("text/html")
    public RestResponse<Object> logout(HttpHeaders httpHeaders, @Context UriInfo uriInfo)
    {
        ResponseBuilder<Object> rr = null;

        /* get hold of the session */
        storage.get().setCookies(httpHeaders.getCookies().values());
        Session s = storage.get().getSession();
        if (s != null) {

            audit.infof("Logout subject=%s",s.id);
            rr = ResponseBuilder.ok();

        } else {

            audit.info("Logout, unknown subject");
            rr = ResponseBuilder.ok();

        }

        storage.get().removeSession();

        return finalizeResponse(rr);
    }
}