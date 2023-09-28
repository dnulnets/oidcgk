package eu.stenlund.session.storage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import org.jboss.logging.Logger;

import eu.stenlund.session.SessionHelper;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Cookie;

/**
 * A specific cookie factory for storing the key in the browser.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public class FrontendKeyStorage extends FrontendStorage<SessionKey> {

    private static final Logger log = Logger.getLogger(FrontendKeyStorage.class);

    /* The helper */
    @Inject SessionHelper sessionHelper;

    /* Number of cookies */
    private int nCookies = 0;

    @Override
    public boolean setCookies(Collection<Cookie> lc) {

        nCookies = sessionHelper.getNumberOfCookiesFromCookie(lc);
        if (nCookies>0) {
            String value = sessionHelper.assembleCookieValuefromCookies(lc, nCookies);
            if (value != null) {
                setInitialValue(sessionHelper.createSessionKeyFromCookieValue(value));
                return true;
            }

        }
        setValue(null);
        return false;
    }

    @Override
    public Collection<Cookie> getCookies () {
        Collection<Cookie> lc = null;

        /* Only generate cookies if the session key have changed */
        if (hasChanged()) {
            try {
                SessionKey key = getValue();            
                if (key != null) {
                    String value = sessionHelper.createCookieValueFromSessionKey(key);
                    return sessionHelper.splitCookieValueIntoCookies(value, nCookies);
                } else {
                    lc = sessionHelper.splitCookieValueIntoCookies(null, nCookies);
                }
            } catch (IOException e) {
                log.error ("OIDCGK: Unable to create session key cookie, removing cookies");
                lc = sessionHelper.splitCookieValueIntoCookies(null, nCookies);
            }
        } else
            lc = new ArrayList<Cookie>();
        return lc;
    }

}
