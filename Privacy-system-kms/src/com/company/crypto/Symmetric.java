package com.company.crypto;

import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

// Class to create a
// symmetric key
public class Symmetric {

    public static final String AES
            = "AES";

    // Function to create a secret key
    public static SecretKey createAESKey()
            throws Exception {

        // Creating a new instance of
        // SecureRandom class.
        SecureRandom secure_random
                = new SecureRandom();

        // Passing the string to
        // KeyGenerator
        KeyGenerator keygenerator
                = KeyGenerator.getInstance(AES);

        // Initializing the KeyGenerator
        // with 256 bits.
        keygenerator.init(256, secure_random);

        return keygenerator.generateKey();
    }


    // TODO: finish symmetric encryption
    public static byte[] aesEncrypt(byte[] original, SecretKey key) {
        return null;
    }

    public static byte[] aesDecrypt(byte[] encrypted, SecretKey key) {
        return null;
    }
}