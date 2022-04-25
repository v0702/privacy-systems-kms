package com.company.hsm;

import com.company.keystructure.DomainKeys;
import com.company.keystructure.Token;
import com.company.keystructure.Trust;
import com.company.utility.CryptographyOperations;

import javax.crypto.SecretKey;
import java.security.*;


/*
* @author victor
*/
public class HardwareSecurityModule extends CryptographyOperations {

    private KeyPair pair;
    private final int keySize;

    public HardwareSecurityModule(int keySize, String algorithm){
        this.keySize = keySize;
        pair = generateKeyPair(this.keySize,algorithm);
        if (pair == null)
            pair = generateKeyPair(2048,"RSA");
    }

    public DomainKeys createDomainKeys(Trust trust) {
        int size = trust.getSize(); //number of public keys in trust
        PublicKey[] trustPublicKeys = trust.getHsmPublicKeys();

        SecretKey key = generateKey(HardwareSecurityModule.AES_KEY_LENGTH_1,"AES"); // the key to protect
        SecretKey freshKey = generateKey(HardwareSecurityModule.AES_KEY_LENGTH_1,"AES"); // the fresh key to wrap the key
        Token masterKeyToken = new Token(encryptAES(key.getEncoded(),freshKey)); // the token of the key

        //TODO: change 10 to the number of public keys we have on the trust
        Token[] freshKeyToken = new Token[size]; // array to store the wrap of the fresh key

        //Encrypt the fresh key with the public keys in the trusts
        for (int i = 0; i< size; ++i) {
            freshKeyToken[i] = new Token(encryptRSA(freshKey.getEncoded(), trustPublicKeys[i]));
        }

        return new DomainKeys(masterKeyToken,freshKeyToken/*TODO: temp, change to trust*/);
    }

    //TODO: should prob not exist, I dont think pk should leave the machine
    public PrivateKey getPrivateKey() {
        return pair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return pair.getPublic();
    }

    public int getKeySize() {
        return keySize;
    }
}
