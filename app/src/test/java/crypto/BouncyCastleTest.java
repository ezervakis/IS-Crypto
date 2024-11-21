package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class BouncyCastleTest {
    public static void main(String[] args) {
        // Add BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Check if BouncyCastle is added
        if (Security.getProvider("BC") != null) {
            System.out.println("BouncyCastle successfully integrated!");
        } else {
            System.out.println("BouncyCastle integration failed.");
        }
    }
}
