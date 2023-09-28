package eu.stenlund.session.storage;

import org.jboss.logging.Logger;

import eu.stenlund.Configuration;
import eu.stenlund.session.SessionHelper;
import io.quarkus.arc.lookup.LookupIfProperty;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;

/**
 * This is storage that stores the entire session in the browser as cookies and do not use any backend storage.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
@RequestScoped
@LookupIfProperty(name = "oidcgk.base.storage", stringValue = "browser")
public class BrowserSessionStorage extends FrontendSessionStorage implements IStorage {

    /* Logger */
    private static final Logger log = Logger.getLogger(BrowserSessionStorage.class);

    /* The configuration */
    @Inject Configuration config;
    
    /* Initialize the session storage */
    @PostConstruct 
    void init() {
        log.info ("Creating the BrowserSessionStorage");
    }

    /* Destroys the session storage */
    @PreDestroy 
    void destroy() {
        log.info ("Destroying the BrowserSessionStorage");
    }

    @Override
    public void addSession(Session s) {

        /* Generate a new session key because this is a new session */
        SessionKey key = SessionHelper.generateSessionKey(config.getOIDCRealm(), false);
        s.id = key.id;
        setValue(s);
    }

    @Override
    public void updateSession(Session s) {
        setValue (s);
    }

    @Override
    public void removeSession() {
        setValue (null);
    }

    @Override
    public Session getSession() {
        return getValue();
    }
    
    @Override
    public SessionKey getSessionKey() {
        SessionKey key = new SessionKey();
        key.id = getValue().id;
        key.cryptoKey = null; /* For browser session storage, we do not have a crypto key */
        return key;
    }
}
