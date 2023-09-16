package eu.stenlund;

/**
 * The generic error used to send back in the response when the api fails.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public class Error {
    
    /**
     * Creates the error with the given error string.
     * 
     * @param error The error string.
     */
    public Error (String error)
    {
        this.error = error;
    }

    /**
     * The error description.
     */
    public String error;

}
