package eu.stenlund;

import org.jboss.logging.Logger;

import jakarta.inject.Singleton;

/**
 * The application class used by the gatekeeper, it contains all global functionality needed.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
@Singleton
public class Application {

    /* Logger */
    private static final Logger log = Logger.getLogger(Application.class);

    /* We are alive and healthy */
    public Boolean live()
    {
       return true;
    }

    /* We are ready to receive requests from istio */
    public Boolean ready ()
    {
        /* In the future we might need to wait for the resource caching has finished first */
        return true;
    }

}
