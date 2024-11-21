package crypto.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Base64;

public class KeyGeneration {
    /**
     * Generates an AES secret key with the specified key size.
     * @param keySize Key size in bits (e.g., 128, 192, 256).
     * @return SecretKey object.
     * @throws Exception if key generation fails.
     */
    public static SecretKey generateKey(int keySize) throws Exception {
        // Add BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Initialize KeyGenerator for AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(keySize); // Key size: 128, 192, or 256 bits

        // Generate and return the secret key
        return keyGen.generateKey();
    }

    public static void main(String[] args) {
        try {
            // Example: Generate a 256-bit AES key
            SecretKey key = generateKey(256);
            System.out.println("Generated Key (Base64): " + Base64.getEncoder().encodeToString(key.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
