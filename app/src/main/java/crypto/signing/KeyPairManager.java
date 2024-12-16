package crypto.signing;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
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
        try (JcaPEMWriter publicWriter = new JcaPEMWriter(new FileWriter(publicKeyPath));
             JcaPEMWriter privateWriter = new JcaPEMWriter(new FileWriter(privateKeyPath))) {
            publicWriter.writeObject(keyPair.getPublic());
            privateWriter.writeObject(keyPair.getPrivate());
        }
    }

    public static KeyPair loadKeyPair(String publicKeyPath, String privateKeyPath) throws IOException {
        try (PEMParser publicParser = new PEMParser(new FileReader(publicKeyPath));
             PEMParser privateParser = new PEMParser(new FileReader(privateKeyPath))) {
            PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) publicParser.readObject());
            PrivateKey privateKey = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) privateParser.readObject());
            return new KeyPair(publicKey, privateKey);
        }
    }
}