package com.nirbhay.security.encryption;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

class AsymmetricEncryptionUtilsTest {

    @Test
    void genrateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPair keyPair = AsymmetricEncryptionUtils.genrateRSAKeyPair();
        Assert.assertNotNull(keyPair);
    }

    @Test
    void geenrateX509Certificate() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtils.genrateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
//        try {
//            CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
//            keyGen.generate(1024);
//
//            //Generate self signed certificate
//            X509Certificate[] chain = new X509Certificate[1];
//            chain[0] = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);
//
//            System.out.println("Certificate : " + chain[0].toString());
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
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