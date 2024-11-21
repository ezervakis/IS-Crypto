# **IS-Crypto**

IS-Crypto is a Java-based cryptographic application that provides functionality for symmetric encryption (AES), asymmetric encryption (RSA), and digital signing and signature verification (DSA). It is designed for educational purposes and built using Gradle as the build tool, with support for Java 21 and JavaFX for future UI integration.

---

## **Features**
1. **Symmetric Encryption (AES)**
   - Generate, store, and use AES secret keys for encryption and decryption.
   - Parameterized support for different key sizes and randomness.

2. **Asymmetric Encryption (RSA)**
   - Generate and persist public/private key pairs in PEM format.
   - Encrypt and decrypt data using RSA keys.

3. **Digital Signing (DSA)**
   - Create and verify digital signatures for data files.
   - Support for key pair generation and persistence.

---

## **Technologies Used**
- **Java 21**: The latest version of Java for modern language features.
- **Gradle 8.8**: Build tool for dependency management and project automation.
- **JUnit 5 (Jupiter)**: For unit testing.
- **JavaFX 21**: For future graphical user interface (UI) development.
- **OpenJFX Libraries**: JavaFX dependencies included via Maven Central.

---

## **Setup Instructions**

### **Prerequisites**
1. **Java 21 or later**: Ensure `JAVA_HOME` points to the JDK installation.
2. **Gradle**: The project includes a Gradle wrapper, so no separate installation is required.
3. **Git**: To clone the repository.

### **Setup Gradle**
1. **Extensions**: Download 'Gradle for Java' and 'Gradle Extension Pack'.
1. **Clean and build the project**: Use `./gradlew clean build`.
2. **Run the application**: Use `./gradlew run`.
3. **Run tests**: Use `./gradlew test`.

---

## **Using the Application**
1. **Main Entry Point**:
   - The application starts from the `App` class located in `src/main/java/crypto/App.java`.
   - Modify `App.java` to add further integration or functionality.

2. **Symmetric Encryption**:
   - Use `SymmetricEncryption` for AES encryption/decryption tasks.

3. **Asymmetric Encryption**:
   - Use `AsymmetricEncryption` for RSA-based public/private key operations.

4. **Digital Signing**:
   - Use `DigitalSigning` to create and verify digital signatures.

---

## **Project Dependencies**
The project uses the following dependencies, managed by Gradle:
- **JUnit 5**: For testing.
- **OpenJFX (JavaFX)**: For GUI (currently planned for future enhancements).

---

## **License**
This project is licensed under the MIT License.

---

## **Troubleshooting**
If you encounter issues:
- Ensure JAVA_HOME is correctly set and matches Java 21.
- Run Gradle with '--stacktrace' for detailed error logs: `./gradlew run --stacktrace`.
- Check that dependencies are downloaded successfully by Gradle.