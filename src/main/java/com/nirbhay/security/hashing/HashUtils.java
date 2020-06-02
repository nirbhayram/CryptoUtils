package com.nirbhay.security.hashing;


import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class HashUtils {

    private static final String SHA = "SHA-256";

    public static byte[] createRandomSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] performSHAHashing(String text, byte[] salt) throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(salt);
        byteArrayOutputStream.write(text.getBytes());
        byte[] valueToHash = byteArrayOutputStream.toByteArray();

        MessageDigest messageDigest = MessageDigest.getInstance(SHA);
        return messageDigest.digest(valueToHash);
    }

    public static String performPasswordHashing(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyPassword(String password, String hashPassword) {
        return BCrypt.checkpw(password, hashPassword);
    }

}
