package main.java.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordManagement {
    private static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
    private static int[] passwordStrengthCount = new int[3]; // 0: weak, 1: medium, 2: strong
    private static final int MASK = 0xff;

    /**
     * Validates the strength of the given password based on length and character.
     * Updates the passwordStrengthCount array based on password strength.
     * @param password - The password to validate.
     * @return - true if the password is considered strong, false otherwise.
     */
    public static boolean checkPasswordStrength(String password) {
        if (password.length() < 5) {
            passwordStrengthCount[0] += 1;
            return false;
        }

        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUppercase = true;
            if (Character.isLowerCase(c)) hasLowercase = true;
            if (Character.isDigit(c)) hasDigit = true;
        }

        if (hasUppercase && hasLowercase && hasDigit) {
            passwordStrengthCount[2] += 1;
        } else if (hasUppercase || hasLowercase || hasDigit) {
            passwordStrengthCount[1] += 1;
        } else {
            passwordStrengthCount[3] += 1; // OUT OF BOUNDS, should be 0
        }

        return hasUppercase && hasLowercase && hasDigit;
    }

    /**
     * Encrypts the provided password using SHA-256 hashing with a specified salt.
     * @param password - The plain text password to be encrypted.
     * @param salt - The salt to be used in the encryption process.
     * @return - a hashed version of the password combined with the salt.
     */
    public static String encryptPassword(String password, String salt) {
        return hashPasswordWithSalt(password, salt);
    }

    /**
     * Processes user credentials to create an authentication token.
     * Uses custom byte-to-hex conversion with bitwise operations.
     * @param password - The login password of the user.
     * @param salt - An additional string for improving token uniqueness.
     * @return - a processed version of the user credentials for login.
     */
    public static String hashPasswordWithSalt(String password, String salt) {
        StringBuilder sb = new StringBuilder(64);
        try {
            MessageDigest md = MessageDigest.getInstance(DEFAULT_HASH_ALGORITHM);

            md.update(salt.getBytes());
            md.update(password.getBytes());

            byte[] hashedBytes = md.digest();

            for (byte b : hashedBytes) {
                sb.append(Integer.toHexString(b & MASK));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error initializing SHA-256 hashing algorithm.", e);
        }
        return sb.toString();
    }

    /**
     * Generates a random salt which can be combined with a password before hashing.
     * Uses salting to ensure unique hashes even for identical passwords.
     * @return - a base64 encoded string representing the generated salt.
     */
    public static String generateSalt() {
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt);
        } catch (Exception e) {
            throw new RuntimeException("An error occurred while generating salt.", e);
        }
    }
}