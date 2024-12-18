package crypto.asymmetric;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

public class KeyPairGeneration {

    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static void saveKeyToFile(String filename, Key key, String description) throws IOException {
        File keyDir = new File("keys");
        if (!keyDir.exists()) {
            keyDir.mkdirs();
        }

        PemObject pemObject = new PemObject(description, key.getEncoded());
        try (PemWriter pemWriter = new PemWriter(new FileWriter(filename))) {
            pemWriter.writeObject(pemObject);
        }
    }

    public static String keyToHex(Key key) {
        return HexFormat.of().formatHex(key.getEncoded());
    }

    public static void generateAndDisplayKeyPair(int keySize) throws Exception {
        KeyPair keyPair = generateKeyPair(keySize);
        System.out.println("Public Key (Hex):\n" + keyToHex(keyPair.getPublic()));
        System.out.println("Private Key (Hex):\n" + keyToHex(keyPair.getPrivate()));
    }

    public static String loadKeyToHex(String filePath) throws IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        return HexFormat.of().formatHex(keyBytes);
    }

    public static PublicKey loadPublicKeyFromPEM(String filepath) throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(filepath))) {
            byte[] content = pemReader.readPemObject().getContent();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new X509EncodedKeySpec(content));
        }
    }

    public static PrivateKey loadPrivateKeyFromPEM(String filepath) throws Exception {
        try (PemReader pemReader = new PemReader(new FileReader(filepath))) {
            byte[] content = pemReader.readPemObject().getContent();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(content));
        }
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return HexFormat.of().formatHex(encryptedBytes);
    }

    public static String decrypt(String encryptedHex, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = HexFormat.of().parseHex(encryptedHex);
        return new String(cipher.doFinal(encryptedBytes));
    }
}
