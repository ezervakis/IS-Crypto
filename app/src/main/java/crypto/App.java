package crypto;

import crypto.shared.KeyStoreManager;
import crypto.symmetric.KeyGeneration;
import crypto.symmetric.SymmetricEncryption;
import crypto.asymmetric.KeyPairGeneration;
import crypto.asymmetric.AsymmetricEncryption;
import crypto.signing.KeyPairManager;
import crypto.signing.DigitalSignatureManager;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.GridPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;

public class App extends Application {
    private SecretKey currentSymmetricKey; // Holds the current AES key
    private KeyPair currentRSAKeyPair; // Holds the current RSA key pair
    private KeyPair currentDSAKeyPair; // Holds the current DSA key pair

    public String getStart() {
        return "Application Started";
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("IS-Crypto");

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

        // Buttons for Symmetric Encryption
        Button generateAESKeyButton = new Button("Generate AES Key");
        Button encryptSymmetricButton = new Button("Encrypt (AES)");
        Button decryptSymmetricButton = new Button("Decrypt (AES)");

        // Buttons for Asymmetric Encryption
        Button generateRSAKeyPairButton = new Button("Generate RSA Key Pair");
        Button encryptAsymmetricButton = new Button("Encrypt (RSA)");
        Button decryptAsymmetricButton = new Button("Decrypt (RSA)");

        // Buttons for Digital Signing
        Button generateDSAKeyPairButton = new Button("Generate DSA Key Pair");
        Button signDataButton = new Button("Sign Data");
        Button verifySignatureButton = new Button("Verify Signature");

        // Clear Button
        Button clearButton = new Button("Clear");

        // Add components to the grid
        grid.add(new Label("Input Text:"), 0, 0);
        grid.add(inputTextArea, 1, 0);
        grid.add(new Label("Output Text:"), 0, 1);
        grid.add(outputTextArea, 1, 1);
        grid.add(generateAESKeyButton, 0, 2);
        grid.add(encryptSymmetricButton, 1, 2);
        grid.add(decryptSymmetricButton, 1, 3);
        grid.add(generateRSAKeyPairButton, 0, 4);
        grid.add(encryptAsymmetricButton, 1, 4);
        grid.add(decryptAsymmetricButton, 1, 5);
        grid.add(generateDSAKeyPairButton, 0, 6);
        grid.add(signDataButton, 1, 6);
        grid.add(verifySignatureButton, 1, 7);
        grid.add(clearButton, 0, 8); // Add the Clear button

        // Button Actions for Symmetric Encryption
        generateAESKeyButton.setOnAction(event -> {
            try {
                currentSymmetricKey = KeyGeneration.generateKey(256);
                KeyStoreManager.storeKey(currentSymmetricKey);
                String keyHex = bytesToHex(currentSymmetricKey.getEncoded());
                outputTextArea.setText("AES Key generated and stored successfully!\nKey (Hex):\n" + keyHex);
            } catch (Exception e) {
                outputTextArea.setText("Error generating AES key: " + e.getMessage());
            }
        });

        encryptSymmetricButton.setOnAction(event -> {
            try {
                if (currentSymmetricKey == null) {
                    outputTextArea.setText("Error: No AES key found. Please generate or load a key first.");
                    return;
                }
                String plaintext = inputTextArea.getText();
                if (plaintext.isEmpty()) {
                    outputTextArea.setText("Error: Please enter text to encrypt.");
                    return;
                }
                String ciphertext = SymmetricEncryption.encrypt(plaintext, currentSymmetricKey);
                outputTextArea.setText("Encrypted Text (Base64):\n" + ciphertext);
            } catch (Exception e) {
                outputTextArea.setText("Error encrypting text: " + e.getMessage());
            }
        });

        decryptSymmetricButton.setOnAction(event -> {
            try {
                if (currentSymmetricKey == null) {
                    outputTextArea.setText("Error: No AES key found. Please generate or load a key first.");
                    return;
                }
                String ciphertext = inputTextArea.getText();
                if (ciphertext.isEmpty()) {
                    outputTextArea.setText("Error: Please enter ciphertext to decrypt.");
                    return;
                }
                String plaintext = SymmetricEncryption.decrypt(ciphertext, currentSymmetricKey);
                outputTextArea.setText("Decrypted Text:\n" + plaintext);
            } catch (Exception e) {
                outputTextArea.setText("Error decrypting text: " + e.getMessage());
            }
        });

        // Button Actions for Asymmetric Encryption
        generateRSAKeyPairButton.setOnAction(event -> {
            try {
                currentRSAKeyPair = KeyPairGeneration.generateKeyPair(2048);
                KeyPairGeneration.saveKeyToFile("rsa_private_key.pem", currentRSAKeyPair.getPrivate(),
                        "RSA PRIVATE KEY");
                KeyPairGeneration.saveKeyToFile("rsa_public_key.pem", currentRSAKeyPair.getPublic(), "RSA PUBLIC KEY");
                outputTextArea.setText(
                        "RSA Key Pair generated and saved successfully!\nPrivate Key: rsa_private_key.pem\nPublic Key: rsa_public_key.pem");
            } catch (Exception e) {
                outputTextArea.setText("Error generating RSA key pair: " + e.getMessage());
            }
        });

        encryptAsymmetricButton.setOnAction(event -> {
            try {
                if (currentRSAKeyPair == null) {
                    outputTextArea.setText("Error: No RSA key pair found. Please generate or load a key pair first.");
                    return;
                }
                String plaintext = inputTextArea.getText();
                if (plaintext.isEmpty()) {
                    outputTextArea.setText("Error: Please enter text to encrypt.");
                    return;
                }
                String ciphertext = AsymmetricEncryption.encrypt(plaintext, currentRSAKeyPair.getPublic());
                outputTextArea.setText("Encrypted Text (Base64):\n" + ciphertext);
            } catch (Exception e) {
                outputTextArea.setText("Error encrypting text: " + e.getMessage());
            }
        });

        decryptAsymmetricButton.setOnAction(event -> {
            try {
                if (currentRSAKeyPair == null) {
                    outputTextArea.setText("Error: No RSA key pair found. Please generate or load a key pair first.");
                    return;
                }
                String ciphertext = inputTextArea.getText();
                if (ciphertext.isEmpty()) {
                    outputTextArea.setText("Error: Please enter ciphertext to decrypt.");
                    return;
                }
                String plaintext = AsymmetricEncryption.decrypt(ciphertext, currentRSAKeyPair.getPrivate());
                outputTextArea.setText("Decrypted Text:\n" + plaintext);
            } catch (Exception e) {
                outputTextArea.setText("Error decrypting text: " + e.getMessage());
            }
        });

        // Button Actions for Digital Signing
        generateDSAKeyPairButton.setOnAction(event -> {
            try {
                currentDSAKeyPair = KeyPairManager.generateDSAKeyPair(2048);
                KeyPairManager.saveKeyPair(currentDSAKeyPair, "dsa_public_key.pem", "dsa_private_key.pem");
                outputTextArea.setText("DSA Key Pair generated and saved successfully!\nPrivate Key: dsa_private_key.pem\nPublic Key: dsa_public_key.pem");
            } catch (Exception e) {
                outputTextArea.setText("Error generating DSA key pair: " + e.getMessage());
            }
        });

        signDataButton.setOnAction(event -> {
            try {
                if (currentDSAKeyPair == null) {
                    outputTextArea.setText("Error: No DSA key pair found. Please generate or load a key pair first.");
                    return;
                }
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Select File to Sign");
                File file = fileChooser.showOpenDialog(primaryStage);
                if (file != null) {
                    byte[] data = Files.readAllBytes(file.toPath());
                    byte[] signature = DigitalSignatureManager.signData(data, currentDSAKeyPair.getPrivate());
                    DigitalSignatureManager.saveSignature(signature, "signature.sig");
                    outputTextArea.setText("Data signed and signature saved to file.");
                }
            } catch (Exception e) {
                outputTextArea.setText("Error signing data: " + e.getMessage());
            }
        });

        verifySignatureButton.setOnAction(event -> {
            try {
                if (currentDSAKeyPair == null) {
                    outputTextArea.setText("Error: No DSA key pair found. Please generate or load a key pair first.");
                    return;
                }
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Select File to Verify");
                File file = fileChooser.showOpenDialog(primaryStage);
                if (file != null) {
                    byte[] data = Files.readAllBytes(file.toPath());
                    byte[] signature = DigitalSignatureManager.loadSignature("signature.sig");
                    boolean isValid = DigitalSignatureManager.verifySignature(data, signature, currentDSAKeyPair.getPublic());
                    outputTextArea.setText("Signature is " + (isValid ? "valid" : "invalid") + ".");
                }
            } catch (Exception e) {
                outputTextArea.setText("Error verifying signature: " + e.getMessage());
            }
        });

        // Clear Button Action
        clearButton.setOnAction(event -> {
            inputTextArea.clear();
            outputTextArea.clear();
        });

        // Drag-and-Drop for Input Text Area
        inputTextArea.setOnDragOver(event -> {
            if (event.getDragboard().hasFiles()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
            event.consume();
        });

        inputTextArea.setOnDragDropped(event -> {
            var dragboard = event.getDragboard();
            if (dragboard.hasFiles()) {
                var file = dragboard.getFiles().get(0);
                if (file.getName().endsWith(".txt")) {
                    try {
                        String content = new String(java.nio.file.Files.readAllBytes(file.toPath()));
                        inputTextArea.setText(content);
                        outputTextArea.setText("File loaded successfully: " + file.getName());
                    } catch (Exception e) {
                        outputTextArea.setText("Error reading file: " + e.getMessage());
                    }
                } else {
                    outputTextArea.setText("Error: Only .txt files are supported.");
                }
            }
            event.setDropCompleted(true);
            event.consume();
        });

        // Set up the scene and show the stage
        Scene scene = new Scene(grid, 600, 600);
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