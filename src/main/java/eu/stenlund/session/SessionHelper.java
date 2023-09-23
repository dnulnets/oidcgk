package eu.stenlund.session;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.NewCookie.SameSite;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import eu.stenlund.Configuration;
import eu.stenlund.session.storage.Session;
import eu.stenlund.session.storage.SessionKey;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.mutiny.tuples.Tuple2;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * The session helper object. It is created during startup and creates the
 * encryption key
 * and helps with handling of session and session cookies throughout the
 * application.
 *
 * @author Tomas Stenlund
 * @since 2022-07-16
 * 
 */
@Singleton
public class SessionHelper {

    private static final Logger log = Logger.getLogger(SessionHelper.class);

    /* Configuration */
    @Inject
    Configuration config;

    /* Get the parser */
    @Inject JWTParser jwtParser;

    /* Our random number generator */
    private final static SecureRandom secureRandom = new SecureRandom();

    /**
     * The max size of cookies betfore they are split up. Should be as close as
     * possible to the
     * max size of cookies.
     */
    private static int COOKIE_MAX_SIZE = 3072;

    /**
     * The key used for encryption and decryption of the cookie. Generated from the
     * oidcgk.cookie.key passphrase provided by the configuration when this class
     * is instantiated.
     */
    private SecretKeySpec secretKey;

    /**
     * The used algorithm for encrypting cookies and server side stored sesions.
     */
    private static String ALGORITHM = "AES/GCM/NoPadding";
    /**
     * The base algorithm.
     */
    private static String ALGORITHM_BASE = "AES";
    /**
     * The length of the IV.
     */
    private static int ALGORITHM_IV_LENGTH = 12;
    /**
     * The length of the AES key.
     */
    private static int ALGORITHM_KEY_LENGTH = 16;

    /**
     * The passphrase algorithm
     */
    private static String ALGORITHM_PASSPHRASE = "PBKDF2WithHmacSHA1";

    /**
     * Creates the helper and sets up the key.
     * 
     * @param COOKIE_KEY The passphrase fpr the cookie
     * @throws NoSuchAlgorithmException The system do not support the algorithm.
     */
    public SessionHelper(@ConfigProperty(name = "oidcgk.cookie.key") String COOKIE_KEY) {
        if (COOKIE_KEY != null) {
            log.info("Using configuration cookie key");
            try {

                byte[] salt = new byte[16];
                secureRandom.nextBytes(salt);
                final KeySpec spec = new PBEKeySpec(COOKIE_KEY.toCharArray(), salt, 65536, ALGORITHM_KEY_LENGTH * 8);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM_PASSPHRASE);
                byte[] hash = factory.generateSecret(spec).getEncoded();
                secretKey = new SecretKeySpec(hash, ALGORITHM_BASE);

            } catch (Exception e) {

                log.warn("Uanble to create a hash of the key, generate a random key");
                log.warn(e.getMessage());
                byte key[] = new byte[ALGORITHM_KEY_LENGTH];
                secureRandom.nextBytes(key);
                secretKey = new SecretKeySpec(key, ALGORITHM_BASE);

            }
        } else {
            log.info("No cookie key has been provided, generate a random key");
            byte key[] = new byte[ALGORITHM_KEY_LENGTH];
            secureRandom.nextBytes(key);
            secretKey = new SecretKeySpec(key, ALGORITHM_BASE);
        }
    }

    /*
     * Generates random UUID to be used in the key generation for session keys
     * 
     * @return A random UUID.
     */
    public static String generateRandomUUID() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    /**
     * Generates a random key
     * 
     * @return A random key.
     */
    private static String generateRandomEncryptionKey() {
        byte key[] = new byte[ALGORITHM_KEY_LENGTH];
        secureRandom.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    /*
     * Generate the session key with a crypto key for storage encryption.
     */

    public static SessionKey generateSessionKey(String realm) {
        return generateSessionKey(realm, true);
    }

    /*
     * Generate the session key and an optional crypto key for storage encryption.
     */
    public static SessionKey generateSessionKey(String realm, boolean bCrypto) {
        SessionKey sk = new SessionKey();
        sk.id = realm + "|" + generateRandomUUID();
        sk.cryptoKey = null;
        if (bCrypto)
            sk.cryptoKey = generateRandomEncryptionKey();
        return sk;
    }

    /**
     * Generate a new IV, encrypt the input and add the IV at the beginning and
     * base64 encode the
     * total.
     * 
     * @param data The data to ecnrypt
     * @return The base64 encoded encrypted data, including the IV.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encrypt(SecretKey secretKey, String aad, byte data[])
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        // Generate a new IV and encrypt the data
        byte[] iv = new byte[ALGORITHM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec param = new GCMParameterSpec(ALGORITHM_KEY_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, param);
        if (aad != null)
            cipher.updateAAD(aad.getBytes());
        byte[] cipherText = cipher.doFinal(data);

        // Add the IV as the first bytes of the buffer before encoding it
        byte[] total = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, total, 0, iv.length);
        System.arraycopy(cipherText, 0, total, iv.length, cipherText.length);

        // Base64 encode the data
        return Base64.getEncoder().encodeToString(total);
    }

    /**
     * Decrypt the data by base64 decode it, taking the first bytes as IV and
     * decrypt the
     * rest of the data.
     * 
     * @param data The base64 encrypted data with IV
     * @return The raw data after decryption.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(SecretKey secretKey, String aad, String data)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        byte[] total = Base64.getDecoder().decode(data);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec param = new GCMParameterSpec(ALGORITHM_KEY_LENGTH * 8, total, 0, ALGORITHM_IV_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, param);
        if (aad != null)
            cipher.updateAAD(aad.getBytes());
        byte[] plainText = cipher.doFinal(total, ALGORITHM_IV_LENGTH, total.length - ALGORITHM_IV_LENGTH);
        return plainText;
    }

    /**
     * Serializes the Session and encrypts the data and create a cookie.
     * 
     * @param s The session.
     * @return A cookie containig the encrypted session.
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String createEncryptedCookieValueFromSession(String context, Session s)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        ByteArrayOutputStream baos = null;
        baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(s);
        oos.close();
        return encrypt(secretKey, context, baos.toByteArray());
    }

    /**
     * Serializes the Session and encrypts the data and create a cookie.
     * 
     * @param s The session.
     * @return A cookie containig the encrypted session.
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String createEncryptedValueFromSession(String context, Session s, String cryptoKey)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        ByteArrayOutputStream baos = null;
        baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(s);
        oos.close();
        byte[] key = Base64.getDecoder().decode(cryptoKey);
        SecretKeySpec sk = new SecretKeySpec(key, ALGORITHM_BASE);
        return encrypt(sk, context, baos.toByteArray());
    }

    /**
     * Serializes the session key to the fornmat <realm>-<id>[-<cryptokey>].
     * 
     * @param key The session key.
     * @return A cookie value containing the session key.
     */
    public String createCookieValueFromSessionKey(SessionKey key) throws IOException {
        if (key.cryptoKey != null)
            return key.id + "|" + key.cryptoKey;
        else
            return key.id;
    }

    /*
     * Creates a cookie with no age, to remove them browser side
     */
    public NewCookie createRemovalCookie(int ix) {
        NewCookie nc = new NewCookie.Builder(config.getCookieName() + "-" + Integer.toString(ix)).httpOnly(true)
                .secure(true)
                .sameSite(SameSite.STRICT).domain(config.getCookieDomain()).path(config.getCookiePath()).maxAge(0)
                .build();
        return nc;
    }

    private Cookie createCookie(int ix, String value) {
        NewCookie nc = new NewCookie.Builder(config.getCookieName() + "-" + Integer.toString(ix)).httpOnly(true)
                .secure(true)
                .sameSite(SameSite.STRICT).domain(config.getCookieDomain()).path(config.getCookiePath()).value(value)
                .maxAge(config.getCookieMaxAge())
                .build();
        return nc;
    }

    /*
     * Create cookies of a value and splits it up depending on size
     */
    public Collection<Cookie> splitCookieValueIntoCookies(String value, int oldNCookies) {
        Collection<Cookie> lc = new ArrayList<>();
        int ix = 0;

        if (value != null) {
            /* Split the string into chunks and create a cookie for each chunk */
            int length = value.length();
            for (int i = 0; i < length; i += COOKIE_MAX_SIZE) {
                String sub = value.substring(i, Math.min(length, i + COOKIE_MAX_SIZE));
                lc.add(createCookie(ix, sub));
                ix++;
            }
        }
        lc.add(createNumberOfCookiesCookie(ix));

        /* Add remove cookies to clear the rest */
        for (int i = ix; i < oldNCookies; i++)
            lc.add(createRemovalCookie(i));

        return lc;
    }

    public int getNumberOfCookiesFromCookie(Collection<Cookie> lc) {
        Optional<Integer> value = lc.stream()
                .filter(cookie -> cookie.getName().compareTo("n" + config.getCookieName()) == 0)
                .findFirst().map(c -> {
                    int n = 0;
                    try {
                        n = Integer.parseInt(c.getValue());
                    } catch (NumberFormatException nfe) {

                    }
                    return n;
                });
        return value.orElse(0);
    }

    private Cookie createNumberOfCookiesCookie(int ix) {
        NewCookie nc = new NewCookie.Builder("n" + config.getCookieName()).httpOnly(true).secure(true)
                .sameSite(SameSite.STRICT)
                .domain(config.getCookieDomain()).path(config.getCookiePath()).value(Integer.toString(ix))
                .maxAge(config.getCookieMaxAge()).build();
        return nc;

    }

    /* A comparator for cookies based on its name */
    private class CookieComparator implements java.util.Comparator<Cookie> {
        @Override
        public int compare(Cookie a, Cookie b) {
            return a.getName().compareTo(b.getName());
        }
    }

    /*
     * Reassemble multiplecookie into one value to circumvent COOKIE_MAX_SIZE
     */
    public String assembleCookieValuefromCookies(Collection<Cookie> lc, int nCookies) {
        final String sw = config.getCookieName() + "-";
        Tuple2<Boolean, String> value = lc.stream().filter(cookie -> cookie.getName().startsWith(sw))
                .sorted(new CookieComparator()).limit(nCookies).map(cookie -> Tuple2.of(true, cookie.getValue()))
                .reduce(Tuple2.of(false, ""),
                        (subtotal, element) -> Tuple2.of(true, subtotal.getItem2() + element.getItem2()));
        if (value.getItem1())
            return value.getItem2();
        else
            return null;
    }

    /**
     * Creates a Session from the encrypted cookie.
     * 
     * @param cookieValue The encrypted cookie.
     * @return The session stored in the cookie.
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public Session createSessionFromEncryptedCookieValue(String context, String cookieValue)
            throws IOException, ClassNotFoundException, InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, BadPaddingException,
            IllegalBlockSizeException {
        Session o = null;
        byte[] data = decrypt(secretKey, context, cookieValue);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        o = (Session) ois.readObject();
        ois.close();

        return o;
    }

    /**
     * Creates a Session from the encrypted value.
     * 
     * @param cookieValue The encrypted cookie.
     * @return The session stored in the cookie.
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static Session createSessionFromEncryptedValue(String context, String cookieValue, String cryptoKey)
            throws IOException, ClassNotFoundException, InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, BadPaddingException,
            IllegalBlockSizeException {
        Session o = null;
        byte[] key = Base64.getDecoder().decode(cryptoKey);
        SecretKeySpec sk = new SecretKeySpec(key, ALGORITHM_BASE);
        byte[] data = decrypt(sk, context, cookieValue);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        o = (Session) ois.readObject();
        ois.close();
        return o;
    }

    /**
     * Converts a cookie to a SessionKey, it must be of format "<realm>-<uid>[-<cryptokey>]"
     * 
     * @param cookie The cookie.
     * @return The sessionkey stored in the cookie.
     */
    public SessionKey createSessionKeyFromCookieValue(String cookie) {
        String[] part = cookie.split("\\|");
        if (part.length == 3) {
            SessionKey sk = new SessionKey();
            sk.id = part[0] + "|" + part[1];
            sk.cryptoKey = part[2];
            return sk;
        } else {
            if (part.length == 2) {
                SessionKey sk = new SessionKey();
                sk.id = part[0] + "|" + part[1];
                return sk;
            } else
                return null;
        }    
    }

    /**
     * Verifies a JWT, checking for expiration, issuer and audience.
     * 
     * @param token The token as a string
     * @param subject The expected subject in the token
     * @return The parsed token
     */
    public JsonWebToken verifyToken(String token, String subject)
    {

        JWTAuthContextInfo jaci = new JWTAuthContextInfo(config.getJWKSEndpoint().toString(), config.getIssuer());
        jaci.setExpectedAudience(config.getAudienceSet());
        jaci.setAlwaysCheckAuthorization(true);
        jaci.setRequireNamedPrincipal(true);
        
        /* Parse the token */
        JsonWebToken jwt = null;
        try {
            jwt = jwtParser.parse(token, jaci);

            /* Same subject as the session says it should be? */
            if (subject != null) {
                if (subject.compareTo(jwt.getSubject())!=0) {
                    log.infof ("Expected subject %s got %s in access token", subject, jwt.getSubject());
                    jwt = null;
                }
            }
            
        } catch (ParseException e) {
            log.infof ("Uable to parse token for subject=%s", subject);
            log.info (e.getMessage());
            jwt = null;
        }

        return jwt;
    }

}