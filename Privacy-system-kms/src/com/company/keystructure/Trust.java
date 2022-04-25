package com.company.keystructure;

import java.security.PublicKey;


/**
 * <pre>
 * The trust to aggregate to the DomainKeys
 *
 * Public keys are of the the hsm and the operators
 *
 * ----------------------------------------------------------------------------------------------
 * |_________________________Trust______________________________________________________________|
 *
 * | Identifier | PublicKey1 | ... | PublicKey_n |   Quorum  |  Predecessor Hash  |  Signature  |
 * |____________|____________|_____|_____________|___________|____________________|_____________|
 *
 *
 *</pre>
 */
public class Trust {
    private final PublicKey[] hsmPublicKeys;
    private final int identifier;
    
    private int counter;
    private final int size;

    public Trust() {
        size = 10;
        counter = 0;
        this.hsmPublicKeys = new PublicKey[size];
    }

    public PublicKey[] getHsmPublicKeys() {
        return hsmPublicKeys;
    }

    /**
     * Go to next public key, if reach last value resets (goes back around).
     * TODO: how to know when it ends?, verify it works
     * @return the public key
     */
    public PublicKey getNextPublicKey() {
        if (counter < size) {
            ++counter;
            return hsmPublicKeys[counter - 1];
        }
        else {
            resetCounter();
            return hsmPublicKeys[counter];
        }
    }

    /**
     * Reset the counter to the first hsm public key.
     */
    public void resetCounter() {
        counter = 0;
    }

    /**
     * Get the size of the public key array.
     *Number of public keys in trust.
     * @return the size of the array that stores public keys.
     */
    public int getSize() {
        return size;
    }

}
