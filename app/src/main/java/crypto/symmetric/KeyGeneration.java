package crypto.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;
import java.util.HexFormat;

public class KeyGeneration {

    /**
     * Generates an AES secret key using BouncyCastle.
     * @param keySize Size of the AES key (128, 192, 256 bits).
     * @return SecretKey object.
     * @throws Exception If key generation fails.
     */
    public static SecretKey generateKey(int keySize) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    /**
     * Displays the generated key in hexadecimal format.
     * @param secretKey Secret key to display.
     * @return Hexadecimal string representation of the key.
     */
    public static String keyToHex(SecretKey secretKey) {
        return HexFormat.of().formatHex(secretKey.getEncoded());
    }
}
