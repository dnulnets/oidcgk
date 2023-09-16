package eu.stenlund.oidc.client;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

/**
 * The REST client for the well known OIDC configuration.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
@Path("/.well-known/openid-configuration")
@RegisterRestClient()
public interface ProviderConfigurationService {
    
    @GET
    @Path("/")
    @Produces("application/json")
    ProviderConfiguration get();

}
