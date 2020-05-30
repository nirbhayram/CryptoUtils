package com.nirbhay.security.keystore;

import com.nirbhay.security.encryption.SymmetricEncryptionUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

class KeyStoreUtilsTest {

    @Test
    void createKeyStore() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException {
        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        KeyStore keyStore = KeyStoreUtils.createKeyStore("keystorepassword", "key-alias", secretKey, "entrypassword");
        //TODO check that keystore is not null

        keyStore.load(null, "keystorepassword".toCharArray());
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("entrypassword".toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("key-alias", entryPassword);
        SecretKey result = secretKeyEntry.getSecretKey();
        //TODO match result hexbinary with secretkey
    }
}