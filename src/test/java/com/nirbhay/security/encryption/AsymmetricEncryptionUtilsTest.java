package com.nirbhay.security.encryption;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

class AsymmetricEncryptionUtilsTest {

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void genrateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPair keyPair = AsymmetricEncryptionUtils.genrateRSAKeyPair();
        //TODO assert null check for the key pair.
        System.out.println(keyPair.getPrivate().getEncoded());
        System.out.println(keyPair.getPublic().getEncoded());
    }

    @Test
    public void testRSAEncryptionDecryption() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        KeyPair keyPair = AsymmetricEncryptionUtils.genrateRSAKeyPair();
        String plianText = "This is string that is to be encrypted by RSA algo.";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plianText, keyPair.getPrivate());
        String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        //TODO check decrypted and plain text matches.
    }

}