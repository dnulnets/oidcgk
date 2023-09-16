package eu.stenlund.session.storage;

import java.io.Serializable;

/**
 * The session key associated with every session. It contains the actual id of the session but also
 * the encryption key used for encrypting server side sessions. It is a unique encryption key for
 * every session and it is stored browser side in a cookie so it will not be located at rest server
 * side, only browser side.
 * 
 * @author Tomas Stenlund
 * @version 1.0
 * @since 1.0
*/
public final class SessionKey implements Serializable {

  /**
   * The version of the serialized key.
   */
  private static final long serialVersionUID = 1L;

  /**
   * The id of the key.
   */
  public String id;
  /**
   * The session encryption key server side.
   */
  public String cryptoKey;

}
