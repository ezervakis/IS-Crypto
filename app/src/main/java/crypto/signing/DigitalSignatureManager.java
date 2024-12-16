package crypto.signing;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class DigitalSignatureManager {

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public static void saveSignature(byte[] signature, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(signature);
        }
    }

    public static byte[] loadSignature(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }
}