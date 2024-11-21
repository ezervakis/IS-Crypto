package crypto;

import org.junit.jupiter.api.Test;

import crypto.symmetric.KeyGeneration;
import crypto.symmetric.KeyStoreManager;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreManagerTest {

    @Test
    void testKeyPersistence() throws Exception {
        // Generate a key
        SecretKey key = KeyGeneration.generateKey(256);

        // Store the key
        KeyStoreManager.storeKey(key);

        // Load the key
        SecretKey loadedKey = KeyStoreManager.loadKey();

        // Verify that the keys are identical
        assertArrayEquals(key.getEncoded(), loadedKey.getEncoded());
    }
}
