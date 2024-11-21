package crypto.symmetric;

import javax.crypto.SecretKey;
import java.util.Scanner;

public class SymmetricEncryptionUI {
    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.println("Choose an option:");
                System.out.println("1. Generate AES Key");
                System.out.println("2. Encrypt Text");
                System.out.println("3. Decrypt Text");
                System.out.println("4. Exit");
                int choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline

                switch (choice) {
                    case 1:
                        SecretKey key = KeyGeneration.generateKey(256);
                        System.out.println("Generated Key (Hex): " + KeyGeneration.keyToHex(key));
                        KeyStoreManager.storeKey(key);
                        System.out.println("Key stored in password-protected keystore.");
                        break;
                    case 2:
                        System.out.print("Enter text to encrypt: ");
                        String plaintext = scanner.nextLine();
                        key = KeyStoreManager.loadKey();
                        String ciphertext = SymmetricEncryption.encrypt(plaintext, key);
                        System.out.println("Encrypted Text (Hex): " + ciphertext);
                        break;
                    case 3:
                        System.out.print("Enter ciphertext to decrypt: ");
                        String cipherInput = scanner.nextLine();
                        key = KeyStoreManager.loadKey();
                        String decryptedText = SymmetricEncryption.decrypt(cipherInput, key);
                        System.out.println("Decrypted Text: " + decryptedText);
                        break;
                    case 4:
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid choice. Try again.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
