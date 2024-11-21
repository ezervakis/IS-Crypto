package crypto.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Security;
import java.util.Base64;

public class SymmetricEncryption {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Encrypts data using AES/GCM/NoPadding.
     * @param plaintext The text to encrypt.
     * @param secretKey The AES secret key.
     * @return The Base64-encoded ciphertext (IV prepended).
     * @throws Exception If encryption fails.
     */
    public static String encrypt(String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new java.security.SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * Decrypts data using AES/GCM/NoPadding.
     * @param ciphertext The Base64-encoded ciphertext (IV prepended).
     * @param secretKey The AES secret key.
     * @return The decrypted plaintext.
     * @throws Exception If decryption fails.
     */
    public static String decrypt(String ciphertext, SecretKey secretKey) throws Exception {
        byte[] data = Base64.getDecoder().decode(ciphertext);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(data, 0, iv, 0, iv.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        byte[] plaintext = cipher.doFinal(data, iv.length, data.length - iv.length);
        return new String(plaintext);
    }
}
