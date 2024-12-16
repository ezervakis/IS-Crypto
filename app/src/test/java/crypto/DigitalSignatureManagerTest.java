package crypto;

import crypto.signing.KeyPairManager;
import crypto.signing.DigitalSignatureManager;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

public class DigitalSignatureManagerTest {

    @Test
    public void testDigitalSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        // Generate a DSA key pair
        KeyPair keyPair = KeyPairManager.generateDSAKeyPair(2048);

        // Data to be signed
        String data = "This is a test message.";
        byte[] dataBytes = data.getBytes();

        // Sign the data
        byte[] signature = DigitalSignatureManager.signData(dataBytes, keyPair.getPrivate());

        // Save the signature to a file
        String signatureFilePath = "test_signature.sig";
        DigitalSignatureManager.saveSignature(signature, signatureFilePath);

        // Load the signature from the file
        byte[] loadedSignature = DigitalSignatureManager.loadSignature(signatureFilePath);

        // Verify the signature
        boolean isValid = DigitalSignatureManager.verifySignature(dataBytes, loadedSignature, keyPair.getPublic());

        // Assert that the signature is valid
        assertTrue(isValid, "The signature should be valid.");
    }
}