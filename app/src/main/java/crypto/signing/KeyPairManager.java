package crypto.signing;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.*;
import java.security.*;

public class KeyPairManager {

    public static KeyPair generateDSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static void saveKeyPair(KeyPair keyPair, String publicKeyPath, String privateKeyPath) throws IOException {
        try (JcaPEMWriter publicWriter = new JcaPEMWriter(new FileWriter(publicKeyPath))) {
            publicWriter.writeObject(keyPair.getPublic());
        }

        try (JcaPEMWriter privateWriter = new JcaPEMWriter(new FileWriter(privateKeyPath))) {
            privateWriter.writeObject(keyPair.getPrivate());
        }
    }

    public static KeyPair loadKeyPair(String publicKeyPath, String privateKeyPath) throws IOException {
        PublicKey publicKey;
        try (PEMParser publicParser = new PEMParser(new FileReader(publicKeyPath))) {
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) publicParser.readObject();
            publicKey = new JcaPEMKeyConverter().getPublicKey(publicKeyInfo);
        }

        PrivateKey privateKey;
        try (PEMParser privateParser = new PEMParser(new FileReader(privateKeyPath))) {
            Object privateObject = privateParser.readObject();

            if (privateObject instanceof PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair) privateObject;
                privateKey = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
            } else if (privateObject instanceof PrivateKeyInfo) {
                privateKey = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) privateObject);
            } else {
                throw new IOException("Invalid private key format");
            }
        }

        return new KeyPair(publicKey, privateKey);
    }
}
