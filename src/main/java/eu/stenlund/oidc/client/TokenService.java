package eu.stenlund.oidc.client;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/")
@RegisterRestClient()
public interface TokenService {
    
    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("application/json")
    Tokens token(@FormParam("client_id") String client_id,
                @FormParam("redirect_uri") String redirect_uri,
                @FormParam("grant_type") String grant_type,
                @FormParam("code") String code,
                @FormParam("client_secret") String client_secret,
                @FormParam("code_verifier") String code_verifier,
                @FormParam("refresh_token") String refresh_token);

}
