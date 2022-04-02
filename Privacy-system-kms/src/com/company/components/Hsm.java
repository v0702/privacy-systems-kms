package com.company.components;

import com.company.crypto.Asymmetric;
import com.company.crypto.Symmetric;
import com.company.domain.DomainKeys;

import java.security.*;
import java.util.Base64;
import java.util.LinkedList;
import javax.crypto.*;

public class Hsm {
    private PrivateKey priv_key;        // Private key asymmetric crypto
    private PublicKey pub_key;          // Public key asymmetric crypto
    private SecretKey master_key;       // Secret key
    private SecretKey user_key;         // Fresh key


    // ---------------------------------------------------------------------

    public Hsm() {
        try {

            KeyPair key_pair = Asymmetric.generateRSAKeyPair();
            this.priv_key = key_pair.getPrivate();
            this.pub_key = key_pair.getPublic();

            this.master_key = Symmetric.createAESKey();
            refreshUserKey();

        } catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    // ---------------------------------------------------------------------


    public PublicKey getPubKey() {
        return pub_key;
    }

    public void refreshUserKey() {
        try {
            this.user_key = Symmetric.createAESKey();
        } catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    public DomainKeys generateDomainKeys(LinkedList<PublicKey> domain_public_keys)  {


        // Convert user key
        byte[] byte_user_key = user_key.getEncoded();
        String string_user_key = Base64.getEncoder().encodeToString(byte_user_key);
        System.out.println("UserKey::" + string_user_key);

        // Encrypt user key foreach public key on domain
        LinkedList<String> domain_keys = new LinkedList<>();
        for ( PublicKey pub_key : domain_public_keys ) {
            byte[] byte_cipher_domain_key = Asymmetric.rsaEncrypt(byte_user_key, pub_key);
            String string_cipher_domain_key = Base64.getEncoder().encodeToString(byte_cipher_domain_key);

            domain_keys.add(string_cipher_domain_key);
        }

        // Convert master key
        byte[] byte_master_key = master_key.getEncoded();
        String string_master_key = Base64.getEncoder().encodeToString(byte_master_key);
        System.out.println("MasterKey::" + string_master_key);

        // Encrypt master key with user_key
        byte[] byte_cipher_master_key = Symmetric.aesEncrypt(byte_master_key, user_key);
        String string_cipher_master_key = Base64.getEncoder().encodeToString(byte_cipher_master_key);


        // Build DomainKeys object
        return new DomainKeys(string_cipher_master_key, domain_keys);
    }


}
