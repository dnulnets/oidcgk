package eu.stenlund.session;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.infinispan.client.hotrod.RemoteCache;
import org.jboss.logging.Logger;

import eu.stenlund.Configuration;
import eu.stenlund.session.storage.IBackendStorage;
import eu.stenlund.session.storage.Session;
import eu.stenlund.session.storage.SessionKey;
import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.infinispan.client.Remote;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@LookupIfProperty(name = "oidcgk.base.storage", stringValue = "infinispan")
public class Infinispan implements IBackendStorage {

    /* Logger */
    private static final Logger log = Logger.getLogger(Infinispan.class);

    /* The session helper */
    @Inject SessionHelper sessionHelper;

    /* The configuration */
    @Inject Configuration config;

    /* Infinispan client */
    @Inject
    @Remote("oidcgk") 
    RemoteCache<String, String> cache; 

    @Override
    public void addSession(SessionKey key, Session s) {
        log.info ("Add a session");
        if (key != null) {
            try {
                String v = SessionHelper.createEncryptedValueFromSession(key.id, s, key.cryptoKey);
                cache.put(key.id, v, config.getTTL(), TimeUnit.SECONDS, config.getTTL(), TimeUnit.SECONDS);
            } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                    | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
                    | IOException e) {
                        log.info("Unable to encrypt session, failed to store the session");
                        log.info(e.getMessage());
            }
        }
    }

    @Override
    public void updateSession(SessionKey key, Session s) {

        if (key != null) {
            try {
                String v = SessionHelper.createEncryptedValueFromSession(key.id, s, key.cryptoKey);
                cache.put(key.id, v, config.getTTL(), TimeUnit.SECONDS, config.getTTL(), TimeUnit.SECONDS);
            } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                    | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
                    | IOException e) {
                        log.info("Unable to encrypt session, failed to store the session");
                        log.info(e.getMessage());
            }
        }
    }

    @Override
    public void removeSession(SessionKey key) {
        if (key != null)
            cache.remove(key.id);
    }

    @Override
    public Session getSession(SessionKey key) {
        if (key != null) {
            String value = cache.get(key.id);
            if (value != null) {
                try {
                    Session s = SessionHelper.createSessionFromEncryptedValue(key.id, value, key.cryptoKey);
                    return s;
                } catch (InvalidKeyException | ClassNotFoundException | NoSuchPaddingException
                        | NoSuchAlgorithmException | InvalidAlgorithmParameterException | BadPaddingException
                        | IllegalBlockSizeException | IOException e) {
                    log.info("Unable to decrypt session, failed to fetch the session from storage");
                    log.info(e.getMessage());
                    return null;
                }
            }
        }
        return null;
    }

}
