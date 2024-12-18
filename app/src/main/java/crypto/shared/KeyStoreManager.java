package crypto.shared;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class KeyStoreManager {

    private static final String KEYSTORE_TYPE = "BCFKS";
    private static final String KEYSTORE_PATH = "keys" + File.separator + "keystore.bcfks";
    private static final String AES_KEY_ALIAS = "aesKey";
    private static final String RSA_KEY_ALIAS = "rsaKey";
    private static final String DSA_KEY_ALIAS = "dsaKey";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyStore loadKeyStore(char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, "BC");
        File keystoreFile = new File(KEYSTORE_PATH);

        if (keystoreFile.exists() && keystoreFile.length() > 0) {
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, password);
            } catch (Exception ex) {
                throw new RuntimeException("Error: Invalid password or corrupted keystore.");
            }
        } else {
            keyStore.load(null, password);
            saveKeyStore(keyStore, password);
        }

        return keyStore;
    }

    public static void saveKeyStore(KeyStore keyStore, char[] password) throws Exception {
        File keyFolder = new File("keys");
        if (!keyFolder.exists()) {
            keyFolder.mkdirs();
        }

        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            keyStore.store(fos, password);
        }
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000);

        X500Name dnName = new X500Name("CN=IS-Crypto, O=Crypto, C=US");
        BigInteger serialNumber = BigInteger.valueOf(now);

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, serialNumber, startDate, endDate, dnName, publicKey);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(privateKey);

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    public static void storeSymmetricKey(SecretKey secretKey, char[] password) throws Exception {
        KeyStore keyStore = loadKeyStore(password);
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(password);

        keyStore.setEntry(AES_KEY_ALIAS, entry, protectionParam);
        saveKeyStore(keyStore, password);
    }

    public static SecretKey loadSymmetricKey(char[] password) throws Exception {
        KeyStore keyStore = loadKeyStore(password);
        if (!keyStore.containsAlias(AES_KEY_ALIAS)) {
            throw new RuntimeException("Error: No AES key found in the keystore.");
        }
        return (SecretKey) keyStore.getKey(AES_KEY_ALIAS, password);
    }

    public static void storeAsymmetricKeyPair(KeyPair keyPair, char[] password) throws Exception {
        KeyStore keyStore = loadKeyStore(password);

        X509Certificate selfSignedCert = generateSelfSignedCertificate(keyPair);
        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(
                keyPair.getPrivate(), new Certificate[] { selfSignedCert });
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(password);

        keyStore.setEntry(RSA_KEY_ALIAS, entry, protectionParam);
        saveKeyStore(keyStore, password);

        saveKeyPairAsPEM(keyPair);
    }

    public static PrivateKey loadPrivateKey(char[] password) throws Exception {
        KeyStore keyStore = loadKeyStore(password);
        if (!keyStore.containsAlias(RSA_KEY_ALIAS)) {
            throw new RuntimeException("Error: No RSA key found in the keystore.");
        }
        return (PrivateKey) keyStore.getKey(RSA_KEY_ALIAS, password);
    }

    public static void saveKeyPairAsPEM(KeyPair keyPair) throws Exception {
        File keyDir = new File("keys");
        if (!keyDir.exists()) {
            keyDir.mkdirs();
        }

        String publicKeyPath = "keys" + File.separator + "publicKey.pem";
        String privateKeyPath = "keys" + File.separator + "privateKey.pem";

        try (PemWriter publicKeyWriter = new PemWriter(new FileWriter(publicKeyPath))) {
            PemObject publicPem = new PemObject("PUBLIC KEY", keyPair.getPublic().getEncoded());
            publicKeyWriter.writeObject(publicPem);
        }

        try (PemWriter privateKeyWriter = new PemWriter(new FileWriter(privateKeyPath))) {
            PemObject privatePem = new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded());
            privateKeyWriter.writeObject(privatePem);
        }
    }

    public static KeyPair loadKeyPairFromPEM(String publicKeyPath, String privateKeyPath) throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyPath));

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(
                new String(privateKeyBytes).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "")));

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(
                new String(publicKeyBytes).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "")));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    public static void storeSigningKeyPair(KeyPair keyPair, char[] password) throws Exception {
        KeyStore keyStore = loadKeyStore(password);

        X509Certificate selfSignedCert = generateSelfSignedCertificate(keyPair);
        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(
                keyPair.getPrivate(), new Certificate[] { selfSignedCert });
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(password);

        keyStore.setEntry(DSA_KEY_ALIAS, entry, protectionParam);
        saveKeyStore(keyStore, password);
    }

    public static PrivateKey loadSigningKey(char[] password) throws Exception {
        KeyStore keyStore = loadKeyStore(password);
        if (!keyStore.containsAlias(DSA_KEY_ALIAS)) {
            throw new RuntimeException("Error: No signing key found in the keystore.");
        }
        return (PrivateKey) keyStore.getKey(DSA_KEY_ALIAS, password);
    }
}
