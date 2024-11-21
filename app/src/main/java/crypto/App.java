package crypto;

import crypto.symmetric.SymmetricEncryptionUI;

import java.util.Scanner;

public class App {
    public String getStart() {
        return "Application Started";
    }

    public static void main(String[] args) {
        System.out.println(new App().getStart());
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.println("Welcome to IS-Crypto Application!");
                System.out.println("Choose a module:");
                System.out.println("1. Symmetric Encryption/Decryption");
                System.out.println("2. Exit");
                System.out.print("Your choice: ");
                int choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline

                switch (choice) {
                    case 1:
                        System.out.println("Launching Symmetric Encryption/Decryption...");
                        SymmetricEncryptionUI.main(null); // Launch SymmetricEncryptionUI
                        break;
                    case 2:
                        System.out.println("Exiting application...");
                        return;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
