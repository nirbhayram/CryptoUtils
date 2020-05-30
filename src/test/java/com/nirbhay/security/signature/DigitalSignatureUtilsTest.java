package com.nirbhay.security.signature;

import com.nirbhay.security.encryption.AsymmetricEncryptionUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

class DigitalSignatureUtilsTest {

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void verifySignature() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        KeyPair keyPair = AsymmetricEncryptionUtils.genrateRSAKeyPair();
        String textToBeSigned = "This is the text that is to be signed.";
        byte[] signedText = DigitalSignatureUtils.createDigitalSignature(textToBeSigned, keyPair.getPrivate());
        boolean result = DigitalSignatureUtils.verifySignature(textToBeSigned, signedText, keyPair.getPublic());
        //TODO assert result value true.
    }
}