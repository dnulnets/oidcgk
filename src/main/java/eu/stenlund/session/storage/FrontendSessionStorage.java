package eu.stenlund.session.storage;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.jboss.logging.Logger;

import eu.stenlund.Configuration;
import eu.stenlund.session.SessionHelper;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Cookie;

/**
 * A specific cookie factory for storing the entire session in the browser.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public class FrontendSessionStorage extends FrontendStorage<Session> {

    private static final Logger log = Logger.getLogger(FrontendSessionStorage.class);

    /* Session helper functionalit */
    @Inject
    SessionHelper sessionHelper;

    /* Configuration */
    @Inject Configuration config;
    
    /* Number of cookies */
    private int nCookies = 0;

    /*
     * Creates the session from the cookie
     */
    @Override
    public boolean setCookies(Collection<Cookie> lc) {

        nCookies = sessionHelper.getNumberOfCookiesFromCookie(lc);
        if (nCookies > 0) {
            String value = sessionHelper.assembleCookieValuefromCookies(lc, nCookies);
            try {
                if (value != null) {
                    setInitialValue(sessionHelper.createSessionFromEncryptedCookieValue(config.getContext(), value));
                    return true;
                }
            } catch (InvalidKeyException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException
                    | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
                    | IOException e) {
                log.infof("Unable to decrypt cookie");
                log.infof(e.getMessage());
            }
        }
        setInitialValue(null);
        return false;
    }

    /*
     * Creates the cookie and encrypt it
     */
    @Override
    public Collection<Cookie> getCookies() {
        Collection<Cookie> lc = null;

        /* Only needs to send the cookies if anythiung has changed */
        if (hasChanged()) {

            try {
                Session s = getValue();
                if (s != null) {
                    String value = sessionHelper.createEncryptedCookieValueFromSession(config.getContext(), s);
                    lc = sessionHelper.splitCookieValueIntoCookies(value, nCookies);

                } else {
                    lc = sessionHelper.splitCookieValueIntoCookies(null, nCookies);
                }

            } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                    | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
                    | IOException e) {
                log.info("Unable to encrypt cookie, removing cookies");
                log.info(e.getMessage());
                lc = sessionHelper.splitCookieValueIntoCookies(null, nCookies);
            }

        } else {
            lc = new ArrayList<Cookie>();
        }

        return lc;
    }

}
