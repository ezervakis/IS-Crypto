package crypto.signing;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class DigitalSigning {

    public static KeyPair generateDSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static void saveKeyPair(KeyPair keyPair, String publicKeyPath, String privateKeyPath) throws IOException {
        try (JcaPEMWriter publicWriter = new JcaPEMWriter(new FileWriter(publicKeyPath));
             JcaPEMWriter privateWriter = new JcaPEMWriter(new FileWriter(privateKeyPath))) {
            publicWriter.writeObject(keyPair.getPublic());
            privateWriter.writeObject(keyPair.getPrivate());
        }
    }

    public static KeyPair loadKeyPair(String publicKeyPath, String privateKeyPath) throws IOException {
        try (PEMParser publicParser = new PEMParser(new FileReader(publicKeyPath));
             PEMParser privateParser = new PEMParser(new FileReader(privateKeyPath))) {
            PublicKey publicKey = new JcaPEMKeyConverter()
                    .getPublicKey((SubjectPublicKeyInfo) publicParser.readObject());
            PrivateKey privateKey = new JcaPEMKeyConverter()
                    .getPrivateKey((PrivateKeyInfo) privateParser.readObject());
            return new KeyPair(publicKey, privateKey);
        }
    }

    public static byte[] signData(byte[] data, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public static void saveSignature(byte[] signature, String filePath) throws IOException {
        Files.write(Paths.get(filePath), signature);
    }

    public static byte[] loadSignature(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    public static void main(String[] args) {
        try {
            String publicKeyPath = "keys/dsa_public.pem";
            String privateKeyPath = "keys/dsa_private.pem";
            String signaturePath = "keys/signature.sig";
            String dataPath = "testfile.txt";

            KeyPair keyPair = generateDSAKeyPair(1024);
            saveKeyPair(keyPair, publicKeyPath, privateKeyPath);
            System.out.println("DSA Key Pair generated and saved successfully.");

            byte[] data = Files.readAllBytes(Paths.get(dataPath));
            byte[] signature = signData(data, keyPair.getPrivate());
            saveSignature(signature, signaturePath);
            System.out.println("Data signed successfully. Signature saved.");

            byte[] loadedSignature = loadSignature(signaturePath);
            boolean isValid = verifySignature(data, loadedSignature, keyPair.getPublic());
            System.out.println("Signature verification result: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
