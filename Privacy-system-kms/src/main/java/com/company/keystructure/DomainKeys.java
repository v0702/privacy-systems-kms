package com.company.keystructure;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.List;

/**
 * <p>
 * Constructor receives the master key and the list of token keys, where
 * token keys is the k used to encrypt mk but encrypted by all the hardware pks
 * </p>
 * <p>
 * Structure to store the master key
 * and the public encrypted key used
 * to encrypt the master key
 * </p>
 * <p>
 * Enc(K,D) -> cipher of D by using K
 * MK is the master key to be protected
 * K is the generated key to wrap the MK
 * Pk1, Pk2, ..., PKi are the Public keys for the HSMs 1 to i
 * </p>
 * <pre>
 * ----------------------------------------------------------
 * |_______________________DomainKeys_______________________|
 * | Enc(Pk1,K) | Enc(Pk2,K) | ... | Enc(Pki,K) | Enc(K,MK) |
 * |____________|____________|_____|____________|___________|
 * </pre>
 * @param masterKeyToken the token for the master key that we want to protect
 * @param wrapKeyTokenList a list of tokens that store the encrypted key
 *                         used to encrypt the master key, this encrypted key is
 *                         itself encrypted by the hsm public keys
 *
 **/
public record DomainKeys(Token masterKeyToken, List<Token> wrapKeyTokenList) implements Serializable {

    /**
     * <p>
     * Get the token of wrap key that was used to encrypt the master key
     * meaning the key that wraps the master key is itself
     * wrapped by the public keys belonging to the hsm's, we find the
     * token (meaning the encryption of the key) that was ciphered by the given
     * hsmPublicKey and return this token
     * </p>
     * @param hsmPublicKey the public key from an hsm, to be used to cross-match and return
     *                     the respective cipher that was created from that same public key
     * @return returns the respective token if found, null if not found
     */
    public Token getWrapKeyToken(PublicKey hsmPublicKey) {
        for (Token wrapKeyToken : wrapKeyTokenList) {
            PublicKey pk = wrapKeyToken.publicKey();
            if (pk != null)
                if (pk.equals(hsmPublicKey))
                    return wrapKeyToken;
        }
        return null;
    }
}
