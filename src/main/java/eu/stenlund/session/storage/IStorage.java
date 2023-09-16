package eu.stenlund.session.storage;

import java.util.Collection;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.ws.rs.core.Cookie;

/**
 * The interface to the storage of sessions for a request.
 * 
 * The storage contains of two parts, the storage at the browser and the storage on the server side which can be
 * anything from plain memory map, redis och infinispan or no server sided storage at all. But storage on the
 * browser side is always used, either for the entire session or for just a key to the session on the server
 * side.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public interface IStorage {

    /**
     * This function initiates the storage with the cookies on the browser side.
     * 
     * @param lc The cookies from the request
     * @return True if the initialization succeded, false otherwise.
     */
    public boolean setCookies (Collection<Cookie> lc);

    /**
     * Converts the storage to cookies that can be stored browser side.
     * 
     * @return A list of cookies.
     */
    public Collection<Cookie> getCookies ();

    /**
     * Tells you if the storage has changed from when it was initialized.
     * 
     * @return True if it has changed, false otherwise.
     */
    public boolean hasChanged();

    /**
     * Adds a new session to the storage, overwrites any old one.
     * 
     * @param s The new session.
     */
    public void addSession(Session s);

    /**
     * Updates the storage with new data on the session.
     * 
     * @param s The updated session.
     */
    public void updateSession (Session s);

    /**
     * Removes the session from storage.
     */
    public void removeSession();

    /**
     * Returns with the current session from the storage.
     * 
     * @return The current session
     */
    public Session getSession();

    /**
     * Returns with the current sessions key.
     * 
     * @return The session key
     */
    public SessionKey getSessionKey();

}