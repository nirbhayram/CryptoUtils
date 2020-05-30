package com.nirbhay.security.encryption;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class SymmetricEncryptionUtilsTest {

    @BeforeEach
    void setUp() {
    }

    @Test
    public void testCreateAESKey() throws NoSuchAlgorithmException {
        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        //TODO check that key is not null
        System.out.println(secretKey.getEncoded());
    }

    @Test
    public void testPerformAESEncryptionDecryption() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        SecretKey key = SymmetricEncryptionUtils.createAESKey();
        //TODO check that key is not null
        byte[] iv = SymmetricEncryptionUtils.createInitializationVector();
        String plainText = "This is plain text which is to be encrypted by AES algo.";
        byte[] cipherText = SymmetricEncryptionUtils.performAESEncryption(plainText, key, iv);
        String decryptedText = SymmetricEncryptionUtils.performAESDecryption(cipherText, key, iv);
        //TODO check plaintext matches with decrypted text
    }

    @AfterEach
    void tearDown() {
    }
}