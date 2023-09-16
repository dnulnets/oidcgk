package eu.stenlund.session.storage;

import java.io.Serializable;

/**
 * The session associated with every request.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public class Session implements Serializable {

    /**
     * The version of the serialized object.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The identity of the session.
     */
    public String id = null;

    /**
     * The redirect URL used for this session to redirect back to the applciation.
     */
    public String redirect_uri = null;

    /**
     * The JWT access token, used upstream by the application.
     */
    public String access_token = null;

    /**
     * The JWT refresh token, used by this gatekeeper to refresh the access and id token.
     */
    public String refresh_token = null;

    /**
     * The JWT id token.
     */
    public String id_token = null;

    @Override
    public String toString ()
    {
        return String.format ("{id=%s,redirect_url=%s,access_token=%s,refresh_token=%s,id_token=%s}", id, redirect_uri, access_token, refresh_token, id_token);
    }

}
