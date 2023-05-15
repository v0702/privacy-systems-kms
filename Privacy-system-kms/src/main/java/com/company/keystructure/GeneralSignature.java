package com.company.keystructure;

import com.company.utility.CryptographyOperations;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Base64;

import static com.company.utility.CryptographyOperations.encodeHexString;
import static com.company.utility.CryptographyOperations.getHashIdentifier;

/**
 * <p>
 * Store a byte array signature and the public key used to verify that same signature.
 * </p>
 * <pre>
 * |---GeneralSignature----|
 * | signature | PublicKey |
 * |-----------------------|
 * </pre>
 * @param signature byte array signature.
 * @param publicKey the public key used to verify the signature.
 */
public record GeneralSignature(byte[] signature, PublicKey publicKey) implements Serializable {

    public String getSignatureHexString() {
        return encodeHexString(this.signature);
    }

    public String getPublicKeyHexString() {
        return encodeHexString(this.publicKey.getEncoded());
    }

    public String getSignatureHash() {
        return getHashIdentifier(this.signature);
    }

    public String getPublicKeyHash() {
        return getHashIdentifier(this.publicKey);
    }

    @Override
    public String toString() {
        String signatureHash = getHashIdentifier(this.signature);
        String signatureBase64 = Base64.getEncoder().encodeToString(this.signature);

        String publicKeyHash = "";
        String publicKeyBase64 = "";
        if (publicKey != null) {
            publicKeyHash = getHashIdentifier(this.publicKey);
            publicKeyBase64 = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
        }
        return  "--------------------------Signature--------------------------\n" +
                "Signature:    "+signatureHash+"\n" +
                "Signature pk: "+publicKeyHash+"\n" +
                "-------------------------------------------------------------\n";

    }

    public GeneralSignature clone() {
        return new GeneralSignature(this.signature().clone(), this.publicKey());
    }
}
