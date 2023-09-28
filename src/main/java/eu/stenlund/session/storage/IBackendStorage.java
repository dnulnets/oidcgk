package eu.stenlund.session.storage;

/**
 * An interface that any backend storage needs to fulfill, it could be for memory, infinispan or
 * redis.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public interface IBackendStorage {

    /**
     * Add a ne wsession to the storage.
     * 
     * @param key The session key
     * @param s The session
     */
    public void addSession( SessionKey key, Session s);

    /**
     * Update the session stored at the session key.
     * 
     * @param key The session key
     * @param s The session
     */
    public void updateSession (SessionKey key, Session s);

    /**
     * Remove the session stored at the session key.
     * 
     * @param key The session key
     */
    public void removeSession(SessionKey key);

    /**
     * Returns with the session stored at the session key.
     * 
     * @param key The session key
     * @return The session
     */
    public Session getSession(SessionKey key);

}
