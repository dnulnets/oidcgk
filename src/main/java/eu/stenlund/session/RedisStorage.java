package eu.stenlund.session;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.jboss.logging.Logger;

import eu.stenlund.Configuration;
import eu.stenlund.session.storage.IBackendStorage;
import eu.stenlund.session.storage.Session;
import eu.stenlund.session.storage.SessionKey;
import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.redis.client.RedisClientName;
import io.quarkus.redis.datasource.ReactiveRedisDataSource;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.ReactiveKeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@LookupIfProperty(name = "oidcgk.base.storage", stringValue = "redis")
public class RedisStorage implements IBackendStorage {

    /* Logger */
    private static final Logger log = Logger.getLogger(RedisStorage.class);

    /* The session helper */
    @Inject SessionHelper sessionHelper;

    /* The configuration */
    @Inject Configuration config;

    /* Redis client */
    private ReactiveKeyCommands<String> keyCommands; 
    private ValueCommands<String, String> valueCommands; 

    /* Creates the client */
    public RedisStorage(@RedisClientName("oidcgk") RedisDataSource ds, @RedisClientName("oidcgk") ReactiveRedisDataSource reactive) { 
        valueCommands = ds.value(String.class);
        keyCommands = reactive.key();
    }

    @Override
    public void addSession(SessionKey key, Session s) {
        if (key != null) {
            String value;
            try {
                value = SessionHelper.createEncryptedValueFromSession(key.id, s, key.cryptoKey);
                valueCommands.setex(key.id, config.getTTL(), value);
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
            String value;
            try {
                value = SessionHelper.createEncryptedValueFromSession(key.id, s, key.cryptoKey);
                valueCommands.setex (key.id, config.getTTL(), value);
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
            keyCommands.del(key.id).await().atMost(Duration.ofSeconds(1));
    }

    @Override
    public Session getSession(SessionKey key) {
        if (key != null) {
            String value = valueCommands.get(key.id);
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
