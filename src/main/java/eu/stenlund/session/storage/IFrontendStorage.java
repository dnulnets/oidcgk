package eu.stenlund.session.storage;

import java.util.Collection;

import jakarta.ws.rs.core.Cookie;

/**
 * A interface that needs to be fulfillde for any implementation that implements frontend storage of
 * any POJO.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public interface IFrontendStorage<T> {

    /**
     * Returns with the value stored at the frontend.
     * 
     * @return The value
     */
    public T getValue();


    /**
     * Stores the value at the frontend and markes it as changed.
     * 
     * @param v The value
     */
    public void setValue(T v);

    /**
     * Stores the value at the frontend and markes it as not changed.
     * 
     * @param v The value
     */
    public void setInitialValue(T v);

    /**
     * Sets the value of the front end storage, based on the cookies.
     * 
     * @param lc A collection of cookies from the request.
     * @return True if the storage could be initialized from the cookies, otherwise false.
     */
    public boolean setCookies (Collection<Cookie> lc);

    /**
     * Get the cookies from the storage.
     * 
     * @return A collection of cookies representing the storage.
     */
    public Collection<Cookie> getCookies ();

    /**
     * Checks if the storage has changed its value.
     * 
     * @return True if it has changed, otherwise false.
     */
    public boolean hasChanged();
}
