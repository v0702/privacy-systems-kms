package com.company.keystructure;

import com.company.utility.CryptographyOperations;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Base64;

/**
 * <p>
 * An encrypted key, usually with another key, stored as a byte array
 * An encrypted key with a given public key
 * </p>
 * @param encryptedKey the encrypted key to store in byte array format
 * @param publicKey public key associated with the encrypted key
 *                  when storing a key pair, store the public key
 *                  of the encrypted private key in here
 */
public record Token(byte[] encryptedKey, PublicKey publicKey) implements Serializable {

    @Override
    public String toString() {
        String encryptedKeyHash = CryptographyOperations.getHashIdentifier(this.encryptedKey);
        String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedKey);

        String publicKeyBase64 = "";
        String publicKeyHash = "";
        if (publicKey != null) {
            publicKeyBase64 = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
            publicKeyHash = CryptographyOperations.getHashIdentifier(this.publicKey);
        }
        return "----------------------------Token----------------------------\n" +
                "|EK: "+encryptedKeyHash+"|\n" +
                "|PK: "+publicKeyHash+"|\n" +
                "-------------------------------------------------------------\n";
    }
}
