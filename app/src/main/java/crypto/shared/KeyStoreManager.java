package crypto.shared;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyStoreManager {

    private static final String KEYSTORE_TYPE = "BCFKS"; // BouncyCastle Keystore
    private static final String KEYSTORE_PATH = "keystore.bcfks";
    private static final String AES_KEY_ALIAS = "aesKey";
    private static final char[] KEYSTORE_PASSWORD = "password123".toCharArray();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ========================
    // Symmetric Key Management
    // ========================

    /**
     * Stores the given AES secret key in the keystore.
     * 
     * @param secretKey The AES key to store.
     * @throws Exception If storing fails.
     */
    public static void storeKey(SecretKey secretKey) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, "BC");
        keyStore.load(null, KEYSTORE_PASSWORD);
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(AES_KEY_ALIAS, entry, new KeyStore.PasswordProtection(KEYSTORE_PASSWORD));

        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            keyStore.store(fos, KEYSTORE_PASSWORD);
        }
    }

    /**
     * Loads the AES secret key from the keystore.
     * 
     * @return The loaded AES key.
     * @throws Exception If loading fails.
     */
    public static SecretKey loadKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, "BC");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            keyStore.load(fis, KEYSTORE_PASSWORD);
        }
        return (SecretKey) keyStore.getKey(AES_KEY_ALIAS, KEYSTORE_PASSWORD);
    }

    // ========================
    // RSA Key Management
    // ========================

    /**
     * Saves an RSA key to a PEM file.
     * 
     * @param filename The file to save to.
     * @param key The key to save (public or private).
     * @param description The description of the key ("RSA PRIVATE KEY" or "RSA PUBLIC KEY").
     * @throws Exception If saving fails.
     */
    public static void saveKeyToPemFile(String filename, Key key, String description) throws Exception {
        PemObject pemObject = new PemObject(description, key.getEncoded());
        try (PemWriter pemWriter = new PemWriter(new FileWriter(filename))) {
            pemWriter.writeObject(pemObject);
        }
    }

    /**
     * Loads an RSA public key from a PEM file.
     * 
     * @param filename The PEM file to load from.
     * @return The loaded public key.
     * @throws Exception If loading fails.
     */
    public static PublicKey loadPublicKeyFromPem(String filename) throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(filename))) {
            byte[] keyBytes = pemReader.readPemObject().getContent();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        }
    }

    /**
     * Loads an RSA private key from a PEM file.
     * 
     * @param filename The PEM file to load from.
     * @return The loaded private key.
     * @throws Exception If loading fails.
     */
    public static PrivateKey loadPrivateKeyFromPem(String filename) throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(filename))) {
            byte[] keyBytes = pemReader.readPemObject().getContent();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    }
}
