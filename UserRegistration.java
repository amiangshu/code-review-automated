package main.java.service;

import main.java.entity.PaymentPreference;
import main.java.entity.User;
import main.java.database.UserDataAccess;
import main.java.database.PaymentPreferenceDataAccess;

import java.util.UUID;

public class UserRegistration {
    private final UserDataAccess db;
    private final PaymentPreferenceDataAccess paymentDb;

    public UserRegistration(UserDataAccess db, PaymentPreferenceDataAccess paymentDb) {
        this.db = db;
        this.paymentDb = paymentDb;
    }

    /**
     * Registers a new user with the given username and password.
     * @param u - The desired username for the new user.
     * @param p - The desired password for the new user.
     * @return - true if the registration was successful, false otherwise.
     */
    public boolean process(String u, String p) {
        if (!isValidInput(u, p)) {
            return false;
        }
        if (userExists(u)) {
            return false;
        }
        String salt = PasswordManagement.generateSalt();
        String encryptedPassword = PasswordManagement.encryptPassword(p, salt);

        return db.addUser(new User(encryptedPassword, salt, u));
    }

    /**
     * Checks if a user with the provided username exists in the database.
     * @param username - The username to check.
     * @return - true if the user exists, false otherwise.
     */
    private boolean userExists(String username) {
        return db.findUserByUsername(username) != null;
    }

    /**
     * Resets the password for the specified user to a default value.
     * Generates a default password for the user, encrypts it using the salt of the user.
     * @param username - The name of the user.
     * @return - true if the password was successfully reset, false otherwise.
     */
    public boolean resetUserPassword(String username) {
        User user = db.findUserByUsername(username);

        String uuidStr = UUID.randomUUID().toString().replaceAll("-", "");
        String defaultPassword = uuidStr.substring(0, 8);

        String encryptedDefaultPassword = PasswordManagement.encryptPassword(defaultPassword, user.getSalt()); // FD: NULL POINTER EXCEPTION
        user.setHashedPassword(encryptedDefaultPassword);

        return db.updateUser(user);
    }

    /**
     * Validates that the provided username and password are not null.
     * @param username - The username to be validated.
     * @param password - The password to be validated.
     * @return - true if both username and password are not null, false otherwise.
     */
    private boolean isValidInput(String username, String password) {
        return username != null && password != null;
    }

    /**
     * Updates the password and preferred payment method for a user.
     * Encrypts the new password with salt and updates the database.
     * @param username - The username of the user to be updated.
     * @param newPassword - The new password to be set for the user.
     * @param newPayment - The new preferred payment method for the user.
     * @return - true if updated successfully, false otherwise.
     */
    public boolean updateUserDetails(String username, String newPassword, String newPayment) {
        User user = db.findUserByUsername(username);
     
        String encryptedNewPassword = PasswordManagement.encryptPassword(newPassword, user.getSalt());
        user.setHashedPassword(encryptedNewPassword);

        PaymentPreference paymentPreference = new PaymentPreference(username, newPayment);
        paymentDb.updatePaymentPreference(paymentPreference);

        return db.updateUser(user);
    }

}