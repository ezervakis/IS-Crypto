package crypto.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;

public class KeyStoreManager {

    private static final String KEYSTORE_TYPE = "BCFKS"; // BouncyCastle Keystore
    private static final String KEYSTORE_PATH = "keystore.bcfks";
    private static final String KEY_ALIAS = "aesKey";
    private static final char[] KEYSTORE_PASSWORD = "password123".toCharArray();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Stores the given secret key in a password-protected keystore.
     * @param secretKey SecretKey to store.
     * @throws Exception If storing fails.
     */
    public static void storeKey(SecretKey secretKey) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, "BC");
        keyStore.load(null, KEYSTORE_PASSWORD);
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(KEY_ALIAS, entry, new KeyStore.PasswordProtection(KEYSTORE_PASSWORD));

        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            keyStore.store(fos, KEYSTORE_PASSWORD);
        }
    }

    /**
     * Retrieves the secret key from the keystore.
     * @return SecretKey object.
     * @throws Exception If retrieval fails.
     */
    public static SecretKey loadKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, "BC");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            keyStore.load(fis, KEYSTORE_PASSWORD);
        }
        return (SecretKey) keyStore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD);
    }
}
