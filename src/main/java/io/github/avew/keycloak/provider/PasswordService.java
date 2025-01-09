package io.github.avew.keycloak.provider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

public class PasswordService {
    public String hash(String password) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            byte[] hash = messageDigest.digest(password.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return hexEncode(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get SHA-1 MessageDigest instance", e);
        }
    }

    private String hexEncode(byte[] bytes) {
        try (Formatter formatter = new Formatter()) {
            for (byte b : bytes) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        }
    }

}
