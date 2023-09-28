package eu.stenlund.oidc.client;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

@Path("/")
@RegisterRestClient()
public interface EndSessionService {
    
    @GET
    @Path("/")
    String logout(@QueryParam("id_token_hint") String id_token_hint,
        @QueryParam("client_id") String client_id);

}
