package com.nirbhay.security.encryption;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

class AsymmetricEncryptionUtilsTest {

    @Test
    void genrateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPair keyPair = AsymmetricEncryptionUtils.genrateRSAKeyPair();
        Assert.assertNotNull(keyPair);
    }

    @Test
    public void testRSAEncryptionDecryption() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        KeyPair keyPair = AsymmetricEncryptionUtils.genrateRSAKeyPair();
        String plianText = "This is string that is to be encrypted by RSA algo.";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plianText, keyPair.getPrivate());
        String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        Assert.assertEquals(plianText, decryptedText);
    }

}