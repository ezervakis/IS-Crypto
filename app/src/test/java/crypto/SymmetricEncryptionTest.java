package crypto;

import org.junit.jupiter.api.Test;

import crypto.symmetric.KeyGeneration;
import crypto.symmetric.SymmetricEncryption;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionTest {

    @Test
    void testEncryptDecrypt() throws Exception {
        // Generate a key
        SecretKey key = KeyGeneration.generateKey(256);

        // Plaintext
        String plaintext = "Hello, IS-Crypto!";

        // Encrypt
        String ciphertext = SymmetricEncryption.encrypt(plaintext, key);
        assertNotNull(ciphertext);

        // Decrypt
        String decryptedText = SymmetricEncryption.decrypt(ciphertext, key);
        assertEquals(plaintext, decryptedText);
    }
}
