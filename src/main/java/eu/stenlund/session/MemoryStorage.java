package eu.stenlund.session;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import eu.stenlund.session.storage.IBackendStorage;
import eu.stenlund.session.storage.Session;
import eu.stenlund.session.storage.SessionKey;
import io.quarkus.arc.lookup.LookupIfProperty;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
@LookupIfProperty(name = "oidcgk.base.storage.backend", stringValue = "memory")
public class MemoryStorage implements IBackendStorage {

    /**
     * The memory storage of our sessions
     */
    Map<String, Session> storage = new ConcurrentHashMap<String, Session>();
    
    @Override
    public void addSession(SessionKey key, Session s) {
        if (key != null)
            storage.put(key.id, s);
    }

    @Override
    public void updateSession(SessionKey key, Session s) {
        if (key != null)
            storage.put(key.id, s);
    }

    @Override
    public void removeSession(SessionKey key) {
        if (key != null)
            storage.remove(key.id);
    }

    @Override
    public Session getSession(SessionKey key) {
        if (key != null)
            return storage.get(key.id);
        else
            return null;
    }

}
