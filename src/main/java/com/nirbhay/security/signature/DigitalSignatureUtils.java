package com.nirbhay.security.signature;

import java.security.*;

public class DigitalSignatureUtils {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static byte[] createDigitalSignature(String inputText, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(key);
        signature.update(inputText.getBytes());
        return signature.sign();
    }

    public static boolean verifySignature(String inputText, byte[] signedText, PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(key);
        signature.update(inputText.getBytes());
        return signature.verify(signedText);
    }

}
