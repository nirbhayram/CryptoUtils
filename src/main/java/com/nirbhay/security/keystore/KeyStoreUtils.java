package com.nirbhay.security.keystore;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class KeyStoreUtils {

    private static final String SECRET_KEY_KEYSTORE_TYPE = "JCEKS";

    public static KeyStore createKeyStore(String keystorePassword, String keyalias, SecretKey secretKey, String entryPassword) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(SECRET_KEY_KEYSTORE_TYPE);
        keyStore.load(null, keystorePassword.toCharArray());
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(entryPassword.toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(keyalias, secretKeyEntry, protectionParameter);
        return keyStore;
    }

}
