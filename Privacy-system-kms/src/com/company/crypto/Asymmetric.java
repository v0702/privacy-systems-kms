package com.company.crypto;

import javax.crypto.Cipher;
import java.security.*;

// Class to create an asymmetric key
public class Asymmetric {

    private static final String RSA
            = "RSA";

    // Generating public and private keys
    // using RSA algorithm.
    public static KeyPair generateRSAKeyPair()
            throws Exception {
        SecureRandom secureRandom
                = new SecureRandom();

        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance(RSA);

        keyPairGenerator.initialize(
                4096, secureRandom);

        return keyPairGenerator
                .generateKeyPair();
    }

    public static byte[] rsaEncrypt(byte[] original, PublicKey key) {
        try {
            // Creating a Cipher object
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // Initaliazing a Cipher object
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // Encrypt the data
            return cipher.doFinal(original);
        } catch ( Exception e ) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] rsaDecrypt(byte[] encrypted, PrivateKey key) {
        try {
            // Creating a Cipher object
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // Initaliazing a Cipher object
            cipher.init(Cipher.DECRYPT_MODE, key);

            // Decrypt the data
            return cipher.doFinal(encrypted);
        } catch ( Exception e ) {
            e.printStackTrace();
        }

        return null;
    }
}
