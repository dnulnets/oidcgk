package eu.stenlund.session.storage;

import org.jboss.logging.Logger;

import eu.stenlund.Configuration;
import eu.stenlund.session.SessionHelper;
import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.arc.lookup.LookupUnlessProperty;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;


/**
 * This is a storage that requires a backend storage, .e.g like memory, redis or infinispan and only sends the key
 * to the browser as a cookie.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
@RequestScoped
@LookupUnlessProperty(name = "oidcgk.base.storage", stringValue = "browser")
public class BrowserKeyStorage extends FrontendKeyStorage implements IStorage {

    /* Logger */
    private static final Logger log = Logger.getLogger(BrowserKeyStorage.class);

    /* Get the configuration */
    @Inject Configuration config;
    
    /* The session helper */
    @Inject SessionHelper sessionHelper;

    /* The backend storage for the session */
    @Inject Instance<IBackendStorage> storage;

    /* Initialize the session storage */
    @PostConstruct 
    void init() {
        log.infof ("Creating the BrowserKeyStorage");
    }

    /* Destroys the session storage */
    @PreDestroy 
    void destroy() {
        log.info ("Destroying the BrowserKeyStorage");
    }

    @Override
    public void addSession(Session s) {
        SessionKey key = SessionHelper.generateSessionKey(config.getOIDCRealm());
        s.id = key.id;
        setValue(key);
        storage.get().addSession(key, s);
    }

    @Override
    public void updateSession(Session s) {
        storage.get().updateSession(getValue(), s);
    }

    @Override
    public void removeSession() {
        storage.get().removeSession(getValue());
        setValue(null);
    }

    @Override
    public Session getSession() {
        SessionKey key = getValue();
        if (key!=null) {
            Session s = storage.get().getSession(key);
            return s;
        } else {
            log.error ("Missing session key");
        }
        return null;
    }

    @Override
    public SessionKey getSessionKey() {
        return getValue();
    }
    
}
