package com.nirbhay.security.hashing;

import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

class HashUtilsTest {

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void performSHAHashing() throws IOException, NoSuchAlgorithmException {
        String textToHash = "This is the text that is to be hashed using sha-256 algo.";
        byte[] salt = HashUtils.createRandomSalt();
        byte[] hashedValue = HashUtils.performSHAHashing(textToHash, salt);
        Assert.assertNotNull(hashedValue);
        byte[] hashedValue2 = HashUtils.performSHAHashing(textToHash, salt);
        Assert.assertEquals(DatatypeConverter.printHexBinary(hashedValue), DatatypeConverter.printHexBinary(hashedValue2));
    }
}