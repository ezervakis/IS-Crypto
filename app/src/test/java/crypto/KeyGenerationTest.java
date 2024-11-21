package crypto;

import org.junit.jupiter.api.Test;

import crypto.symmetric.KeyGeneration;

import javax.crypto.SecretKey;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class KeyGenerationTest {

    @Test
    void testGenerateKey() throws Exception {
        SecretKey key = KeyGeneration.generateKey(256);
        assertNotNull(key);
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes
    }

    @Test
    void testKeyToHex() throws Exception {
        SecretKey key = KeyGeneration.generateKey(128);
        String hexKey = KeyGeneration.keyToHex(key);
        assertNotNull(hexKey);
        assertEquals(32, hexKey.length()); // 128 bits = 16 bytes = 32 hex chars
    }
}
