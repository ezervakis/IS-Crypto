package crypto;

import crypto.symmetric.KeyGeneration;
import crypto.symmetric.KeyStoreManager;
import crypto.symmetric.SymmetricEncryption;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;

import javax.crypto.SecretKey;

public class App extends Application {
    private SecretKey currentKey; // Holds the current AES key

    public String getStart() {
        return "Application Started";
    }
    
    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Symmetric Encryption");

        // Create a grid layout
        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setVgap(10);
        grid.setHgap(10);

        // Input and Output fields
        TextArea inputTextArea = new TextArea();
        inputTextArea.setPromptText("Enter text to encrypt or decrypt...");
        TextArea outputTextArea = new TextArea();
        outputTextArea.setPromptText("Output will appear here...");
        outputTextArea.setEditable(false);

        // Buttons
        Button generateKeyButton = new Button("Generate AES Key");
        Button encryptButton = new Button("Encrypt");
        Button decryptButton = new Button("Decrypt");

        // Add components to the grid
        grid.add(new Label("Input Text:"), 0, 0);
        grid.add(inputTextArea, 1, 0);
        grid.add(new Label("Output Text:"), 0, 1);
        grid.add(outputTextArea, 1, 1);
        grid.add(generateKeyButton, 0, 2);
        grid.add(encryptButton, 1, 2);
        grid.add(decryptButton, 1, 3);

        // Button Actions
        generateKeyButton.setOnAction(event -> {
            try {
                currentKey = KeyGeneration.generateKey(256);
                KeyStoreManager.storeKey(currentKey);
                String keyHex = bytesToHex(currentKey.getEncoded());
                outputTextArea.setText("Key generated and stored successfully!\nAES Key (Hex):\n" + keyHex);
            } catch (Exception e) {
                outputTextArea.setText("Error generating key: " + e.getMessage());
            }
        });

        encryptButton.setOnAction(event -> {
            try {
                if (currentKey == null) {
                    outputTextArea.setText("Error: No key found. Please generate or load a key before encrypting.");
                    return;
                }
                String plaintext = inputTextArea.getText();
                if (plaintext.isEmpty()) {
                    outputTextArea.setText("Error: Please enter text to encrypt.");
                    return;
                }
                String ciphertext = SymmetricEncryption.encrypt(plaintext, currentKey);
                outputTextArea.setText("Encrypted Text (Base64):\n" + ciphertext);
            } catch (Exception e) {
                outputTextArea.setText("Error encrypting text: " + e.getMessage());
            }
        });

        decryptButton.setOnAction(event -> {
            try {
                if (currentKey == null) {
                    outputTextArea.setText("Error: No key found. Please generate or load a key before decrypting.");
                    return;
                }
                String ciphertext = inputTextArea.getText();
                if (ciphertext.isEmpty()) {
                    outputTextArea.setText("Error: Please enter ciphertext to decrypt.");
                    return;
                }
                String plaintext = SymmetricEncryption.decrypt(ciphertext, currentKey);
                outputTextArea.setText("Decrypted Text:\n" + plaintext);
            } catch (Exception e) {
                outputTextArea.setText("Error decrypting text: " + e.getMessage());
            }
        });

        // Set up the scene and show the stage
        Scene scene = new Scene(grid, 600, 400);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    // Utility method to convert byte array to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
