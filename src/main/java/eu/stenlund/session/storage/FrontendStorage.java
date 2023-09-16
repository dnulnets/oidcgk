package eu.stenlund.session.storage;

import jakarta.enterprise.context.RequestScoped;

/**
 * A class for storage at the browser regardless of the type of the POJO to store. It only contains
 * generic functions.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public abstract class FrontendStorage<T> implements IFrontendStorage<T> {
    
    /* The item that we save */
    private T item = null;
    private boolean changed = false;

    @Override
    public T getValue() {
        return item;
    }

    @Override
    public void setValue(T o) {
        item = o;
        changed = true;
    }

    @Override
    public void setInitialValue(T o)
    {
        item = o;
        changed = false;
    }

    @Override
    public boolean hasChanged() {
        return changed;
    }
}
