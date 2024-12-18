package crypto;

import crypto.asymmetric.KeyPairGeneration;
import crypto.shared.KeyStoreManager;
import crypto.signing.DigitalSigning;
import crypto.signing.KeyPairManager;
import crypto.symmetric.KeyGeneration;
import crypto.symmetric.SymmetricEncryption;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HexFormat;

import javax.crypto.SecretKey;

public class App extends Application {

    private static char[] keystorePassword;
    private boolean keysGenerated = false;

    private boolean isValidHex(String text) {
        return text.matches("^[0-9A-Fa-f]+$");
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("IS-Crypto");
        promptForPassword();
        TabPane tabPane = new TabPane();
        Tab symmetricTab = createSymmetricTab();
        Tab asymmetricTab = createAsymmetricTab();
        Tab signingTab = createSigningTab();
        tabPane.getTabs().addAll(symmetricTab, asymmetricTab, signingTab);
        VBox mainLayout = new VBox(10);
        mainLayout.setPadding(new Insets(10));
        mainLayout.getChildren().addAll(tabPane);
        Button clearButton = new Button("Clear All");
        clearButton.setOnAction(e -> clearAllTextAreas(tabPane));
        mainLayout.getChildren().add(clearButton);
        Scene scene = new Scene(mainLayout, 800, 600);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void promptForPassword() {
        boolean validPassword = false;
        while (!validPassword) {
            TextInputDialog passwordDialog = new TextInputDialog();
            passwordDialog.setTitle("Keystore Password");
            passwordDialog.setHeaderText("Enter the Keystore Password:");
            passwordDialog.setContentText("Password:");
            passwordDialog.showAndWait().ifPresent(password -> keystorePassword = password.toCharArray());
            if (keystorePassword == null || keystorePassword.length == 0) {
                showError(new RuntimeException("Password is required to use the application."));
                System.exit(1);
            }
            try {
                KeyStoreManager.loadKeyStore(keystorePassword);
                validPassword = true;
                showInfo("Keystore loaded successfully.");
            } catch (Exception ex) {
                showError(new RuntimeException("Invalid password. Please try again."));
            }
        }
    }

    private Tab createSymmetricTab() {
        Tab tab = new Tab("Symmetric Encryption");
        tab.setClosable(false);
        VBox layout = new VBox(10);
        layout.setPadding(new Insets(10));
        Label keySizeLabel = new Label("Key Size:");
        ComboBox<Integer> keySizeBox = new ComboBox<>();
        keySizeBox.getItems().addAll(128, 192, 256);
        keySizeBox.setValue(256);
        Label randomnessLabel = new Label("Randomness Source:");
        ComboBox<String> randomnessBox = new ComboBox<>();
        randomnessBox.getItems().addAll("Default", "SecureRandom");
        randomnessBox.setValue("Default");
        Label keyLabel = new Label("Generated Key (Hex):");
        TextField keyField = new TextField();
        keyField.setEditable(false);
        Button generateKeyButton = new Button("Generate AES Key");
        Label inputLabel = new Label("Input Text or File:");
        TextArea inputArea = new TextArea();
        Button loadFileButton = new Button("Load File");
        Button saveFileButton = new Button("Save Encrypted Data");
        Button encryptButton = new Button("Encrypt");
        Button decryptButton = new Button("Decrypt");
        Label resultLabel = new Label("Result (Hex):");
        TextArea resultArea = new TextArea();
        resultArea.setEditable(false);
        FileChooser fileChooser = new FileChooser();

        generateKeyButton.setOnAction(e -> {
            try {
                int keySize = keySizeBox.getValue();
                SecretKey key = KeyGeneration.generateKey(keySize);
                KeyStoreManager.storeSymmetricKey(key, keystorePassword);
                keyField.setText(KeyGeneration.keyToHex(key));
                showInfo("AES Key generated successfully with " + randomnessBox.getValue() + ".");
            } catch (Exception ex) {
                showError(ex);
            }
        });

        saveFileButton.setOnAction(e -> {
            fileChooser.setInitialFileName("AES_Encrypted_Message.txt");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
            File file = fileChooser.showSaveDialog(null);
            if (file != null) {
                try {
                    Files.writeString(file.toPath(), resultArea.getText(), java.nio.charset.StandardCharsets.UTF_8);
                    showInfo("Encrypted data saved successfully.");
                } catch (Exception ex) {
                    showError(new RuntimeException("Failed to save file."));
                }
            }
        });

        loadFileButton.setOnAction(e -> {
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
            File file = fileChooser.showOpenDialog(null);
            if (file != null) {
                try {
                    String content = Files.readString(file.toPath(), java.nio.charset.StandardCharsets.UTF_8);
                    inputArea.setText(content);
                    showInfo("File loaded successfully.");
                } catch (Exception ex) {
                    showError(new RuntimeException("Failed to load file."));
                }
            }
        });

        encryptButton.setOnAction(e -> {
            try {
                if (inputArea.getText().isEmpty()) {
                    throw new RuntimeException("Input area is empty. Please enter text or load a file to encrypt.");
                }
                SecretKey key = KeyStoreManager.loadSymmetricKey(keystorePassword);
                if (key == null) {
                    throw new RuntimeException("No AES key found. Please generate a key before encrypting.");
                }
                String randomnessSource = randomnessBox.getValue();
                SecureRandom random = randomnessSource.equals("SecureRandom") ? new SecureRandom() : null;
                byte[] encryptedBytes = SymmetricEncryption.encryptToBytes(inputArea.getText(), key, random);
                String hexEncrypted = HexFormat.of().formatHex(encryptedBytes);
                resultArea.setText(hexEncrypted);
                showInfo("Data encrypted successfully.");
            } catch (Exception ex) {
                showError(ex);
            }
        });

        decryptButton.setOnAction(e -> {
            try {
                if (resultArea.getText().isEmpty()) {
                    throw new RuntimeException("No encrypted data found. Please enter or load encrypted text.");
                }
                SecretKey key = KeyStoreManager.loadSymmetricKey(keystorePassword);
                if (key == null) {
                    throw new RuntimeException("No AES key found. Please generate a key before decrypting.");
                }
                byte[] encryptedBytes = HexFormat.of().parseHex(resultArea.getText());
                String decrypted = SymmetricEncryption.decryptFromBytes(encryptedBytes, key);
                resultArea.setText(decrypted);
                showInfo("Data decrypted successfully.");
            } catch (Exception ex) {
                showError(new RuntimeException("Decryption failed. Ensure you use the correct key and input."));
            }
        });

        layout.getChildren().addAll(
                keySizeLabel, keySizeBox, randomnessLabel, randomnessBox,
                keyLabel, keyField, generateKeyButton,
                inputLabel, inputArea, loadFileButton, saveFileButton,
                encryptButton, decryptButton, resultLabel, resultArea);

        tab.setContent(layout);
        return tab;
    }

    private Tab createAsymmetricTab() {
        Tab tab = new Tab("Asymmetric Encryption");
        tab.setClosable(false);

        VBox layout = new VBox(10);
        layout.setPadding(new Insets(10));

        Label keySizeLabel = new Label("Key Size:");
        ComboBox<Integer> keySizeBox = new ComboBox<>();
        keySizeBox.getItems().addAll(1024, 2048, 4096);
        keySizeBox.setValue(2048);

        Label randomnessLabel = new Label("Randomness Source:");
        ComboBox<String> randomnessBox = new ComboBox<>();
        randomnessBox.getItems().addAll("Default", "SecureRandom");
        randomnessBox.setValue("Default");

        Label keyLabel = new Label("Generated Keys (Hex):");
        TextArea publicKeyArea = new TextArea();
        publicKeyArea.setPromptText("Public Key Hex");
        publicKeyArea.setEditable(false);

        TextArea privateKeyArea = new TextArea();
        privateKeyArea.setPromptText("Private Key Hex");
        privateKeyArea.setEditable(false);

        Button generateKeysButton = new Button("Generate RSA Key Pair");

        Label inputLabel = new Label("Input Text or File:");
        TextArea inputArea = new TextArea();

        Button loadFileButton = new Button("Load File");
        Button saveFileButton = new Button("Save Encrypted Data");

        Button encryptButton = new Button("Encrypt");
        Button decryptButton = new Button("Decrypt");

        Label resultLabel = new Label("Result (Hex):");
        TextArea resultArea = new TextArea();
        resultArea.setEditable(false);

        FileChooser fileChooser = new FileChooser();

        generateKeysButton.setOnAction(e -> {
            try {
                SecureRandom random;
                if ("SecureRandom".equals(randomnessBox.getValue())) {
                    random = new SecureRandom();
                } else {
                    random = new SecureRandom();
                }

                int keySize = keySizeBox.getValue();
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(keySize, random);
                KeyPair keyPair = keyGen.generateKeyPair();

                KeyPairGeneration.saveKeyToFile("keys" + File.separator + "publicKey.pem", keyPair.getPublic(),
                        "PUBLIC KEY");
                KeyPairGeneration.saveKeyToFile("keys" + File.separator + "privateKey.pem", keyPair.getPrivate(),
                        "PRIVATE KEY");

                publicKeyArea.setText(KeyPairGeneration.keyToHex(keyPair.getPublic()));
                privateKeyArea.setText(KeyPairGeneration.keyToHex(keyPair.getPrivate()));

                showInfo("RSA Key Pair generated successfully with " + randomnessBox.getValue() + ".");
            } catch (Exception ex) {
                showError(ex);
            }
        });

        loadFileButton.setOnAction(e -> {
            fileChooser.setTitle("Open Text File");
            fileChooser.getExtensionFilters().clear();
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
            File file = fileChooser.showOpenDialog(null);

            if (file != null) {
                try {
                    String content = Files.readString(file.toPath());
                    inputArea.setText(content);
                    showInfo("File loaded successfully.");
                } catch (Exception ex) {
                    showError(new RuntimeException("Failed to load file."));
                }
            }
        });

        saveFileButton.setOnAction(e -> {
            fileChooser.setTitle("Save Encrypted Data");
            fileChooser.getExtensionFilters().clear();
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
            fileChooser.setInitialFileName("RSA_Encrypted_Message.txt");
            File file = fileChooser.showSaveDialog(null);

            if (file != null) {
                try {
                    Files.writeString(file.toPath(), resultArea.getText());
                    showInfo("Encrypted data saved successfully to: " + file.getName());
                } catch (Exception ex) {
                    showError(new RuntimeException("Failed to save file."));
                }
            }
        });

        encryptButton.setOnAction(e -> {
            try {
                if (inputArea.getText().isEmpty()) {
                    throw new RuntimeException("Input area is empty. Please enter text or load a file to encrypt.");
                }

                File publicKeyFile = new File("keys" + File.separator + "publicKey.pem");
                if (!publicKeyFile.exists()) {
                    throw new RuntimeException("Public key not found. Please generate a key pair first.");
                }

                PublicKey publicKey = KeyPairGeneration.loadPublicKeyFromPEM("keys" + File.separator + "publicKey.pem");
                String encryptedData = KeyPairGeneration.encrypt(inputArea.getText(), publicKey);
                resultArea.setText(encryptedData);
                showInfo("Data encrypted successfully.");
            } catch (Exception ex) {
                showError(ex);
            }
        });

        decryptButton.setOnAction(e -> {
            try {
                if (resultArea.getText().isEmpty()) {
                    throw new RuntimeException("No encrypted data found. Please enter or load encrypted text.");
                }

                String encryptedText = resultArea.getText().trim();

                if (!isValidHex(encryptedText)) {
                    throw new RuntimeException("Invalid encrypted data format. Ensure the input is valid hexadecimal.");
                }

                File privateKeyFile = new File("keys" + File.separator + "privateKey.pem");
                if (!privateKeyFile.exists()) {
                    throw new RuntimeException("Private key not found. Please generate a key pair first.");
                }

                PrivateKey privateKey = KeyPairGeneration
                        .loadPrivateKeyFromPEM("keys" + File.separator + "privateKey.pem");
                String decryptedData = KeyPairGeneration.decrypt(encryptedText, privateKey);
                resultArea.setText(decryptedData);
                showInfo("Data decrypted successfully.");
            } catch (RuntimeException ex) {
                showError(ex);
            } catch (Exception ex) {
                showError(new RuntimeException("Decryption failed. Ensure you use the correct key and input."));
            }
        });

        layout.getChildren().addAll(
                keySizeLabel, keySizeBox, randomnessLabel, randomnessBox,
                keyLabel, publicKeyArea, privateKeyArea, generateKeysButton,
                inputLabel, inputArea, loadFileButton, saveFileButton, encryptButton, decryptButton,
                resultLabel, resultArea);

        tab.setContent(layout);
        return tab;
    }

    private Tab createSigningTab() {
        Tab tab = new Tab("Digital Signing");
        tab.setClosable(false);

        VBox layout = new VBox(10);
        layout.setPadding(new Insets(10));

        Label messageLabel = new Label("File to Sign:");
        TextField filePathField = new TextField();
        Button browseButton = new Button("Browse");

        CheckBox reuseKeyCheckBox = new CheckBox("Reuse Existing Key Pair");

        // Randomness Source Selection
        Label randomnessLabel = new Label("Randomness Source:");
        ComboBox<String> randomnessBox = new ComboBox<>();
        randomnessBox.getItems().addAll("Default", "SecureRandom");
        randomnessBox.setValue("Default");

        Button generateKeyPairButton = new Button("Generate Key Pair");
        Button signButton = new Button("Sign");
        Button verifyButton = new Button("Verify");

        browseButton.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            File file = fileChooser.showOpenDialog(null);
            if (file != null)
                filePathField.setText(file.getAbsolutePath());
        });

        // Generate Key Pair with randomness source
        generateKeyPairButton.setOnAction(e -> {
            try {
                SecureRandom random;
                if ("SecureRandom".equals(randomnessBox.getValue())) {
                    random = new SecureRandom();
                } else {
                    random = new SecureRandom(); // Default behavior
                }

                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
                keyGen.initialize(1024, random);
                KeyPair keyPair = keyGen.generateKeyPair();

                KeyPairManager.saveKeyPair(keyPair, "keys/dsa_public.pem", "keys/dsa_private.pem");
                keysGenerated = true;

                showInfo("DSA Key Pair generated successfully with " + randomnessBox.getValue() + ".");
            } catch (Exception ex) {
                showError(ex);
            }
        });

        signButton.setOnAction(e -> {
            try {
                KeyPair keyPair = null;
                File publicKeyFile = new File("keys/dsa_public.pem");
                File privateKeyFile = new File("keys/dsa_private.pem");

                if (keysGenerated) {
                    keyPair = KeyPairManager.loadKeyPair("keys/dsa_public.pem", "keys/dsa_private.pem");
                    showInfo("Using freshly generated DSA key pair.");
                } else if (reuseKeyCheckBox.isSelected()) {
                    if (!publicKeyFile.exists() || !privateKeyFile.exists()) {
                        throw new RuntimeException("No existing key pair found. Please generate a key pair first.");
                    }
                    keyPair = KeyPairManager.loadKeyPair("keys/dsa_public.pem", "keys/dsa_private.pem");
                    showInfo("Reusing existing DSA key pair.");
                } else {
                    throw new RuntimeException("No key pair found. Please generate a key pair before signing.");
                }

                if (filePathField.getText().isEmpty()) {
                    throw new RuntimeException("No file selected. Please browse and select a file to sign.");
                }

                byte[] data = Files.readAllBytes(Paths.get(filePathField.getText()));
                byte[] signature = DigitalSigning.signData(data, keyPair.getPrivate());
                DigitalSigning.saveSignature(signature, "keys/signature.sig");
                showInfo("Signature saved as 'keys/signature.sig'.");

                keysGenerated = false;

            } catch (Exception ex) {
                showError(ex);
            }
        });

        verifyButton.setOnAction(e -> {
            try {
                if (filePathField.getText().isEmpty()) {
                    throw new RuntimeException("No file selected. Please browse and select a file to verify.");
                }

                File signatureFile = new File("keys/signature.sig");
                File publicKeyFile = new File("keys/dsa_public.pem");

                if (!signatureFile.exists()) {
                    throw new RuntimeException("No signature file found. Please sign a file before verifying.");
                }

                if (!publicKeyFile.exists()) {
                    throw new RuntimeException("No public key found. Please generate or reuse a key pair first.");
                }

                byte[] data = Files.readAllBytes(Paths.get(filePathField.getText()));
                byte[] signature = DigitalSigning.loadSignature("keys/signature.sig");
                PublicKey publicKey = KeyPairManager.loadKeyPair("keys/dsa_public.pem", "keys/dsa_private.pem")
                        .getPublic();

                boolean valid = DigitalSigning.verifySignature(data, signature, publicKey);

                if (valid) {
                    showInfo("Signature is valid!");
                } else {
                    showError(new RuntimeException("Signature is invalid. File verification failed."));
                }

            } catch (Exception ex) {
                showError(ex);
            }
        });

        layout.getChildren().addAll(
                messageLabel, filePathField, browseButton,
                randomnessLabel, randomnessBox, generateKeyPairButton,
                reuseKeyCheckBox, signButton, verifyButton);

        tab.setContent(layout);
        return tab;
    }

    private void clearAllTextAreas(TabPane tabPane) {
        for (Tab tab : tabPane.getTabs()) {
            if (tab.getContent() instanceof VBox) {
                VBox vbox = (VBox) tab.getContent();
                for (javafx.scene.Node node : vbox.getChildren()) {
                    if (node instanceof TextArea) {
                        TextArea textArea = (TextArea) node;
                        if (!textArea.getPromptText().toLowerCase().contains("key")) {
                            textArea.clear();
                        }
                    }
                }
            }
        }
        showInfo("UI cleared. Keys remain loaded in memory.");
    }

    private void showError(Exception ex) {
        Alert alert = new Alert(Alert.AlertType.ERROR, ex.getMessage());
        alert.showAndWait();
    }

    private void showInfo(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION, message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
