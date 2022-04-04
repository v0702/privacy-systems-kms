package com.company;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * <pre>
 *
 *Enc(K,D) -> cipher of D by using K
 *MK is the master key to be protected
 *K is the generated key to wrap the MK
 *Pk1, Pk2, ..., PKi are the Public keys for the HSMs 1 to i
 *
 *----------------------------------------------------------
 *|_______________________DomainKeys_______________________|
 *
 *| Enc(Pk1,K) | Enc(Pk2,K) | ... | Enc(Pki,K) | Enc(K,MK) |
 *|____________|____________|_____|____________|___________|
 *
 *</pre>
 **/
public class DomainKeys {
    private SecretKey masterKeyToken;
    private SecretKey[] tokenKeys;

    public DomainKeys(SecretKey masterKeyToken, SecretKey[] tokenKeys) {
        this.masterKeyToken = masterKeyToken;
        this.tokenKeys = tokenKeys;
    }

    public static SecretKey ByteToSecretKey(byte[] key, String algorithm){
        return new SecretKeySpec(key,algorithm);
    }

    public SecretKey[] getTokenKey() {
        return tokenKeys;
    }

    public void setTokenKey(SecretKey[] tokenKey) {
        this.tokenKeys = tokenKeys;
    }
}
