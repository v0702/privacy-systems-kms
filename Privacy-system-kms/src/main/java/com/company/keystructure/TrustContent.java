package com.company.keystructure;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * The trustContent to aggregate to the DomainKeys
 *
 * 1. Unique identifier of the trustContent
 *
 * 2. Public keys are of the the hsm and the operators
 *
 * 3. Quorum is the rules: the operators that can manage and
 *    the qualified set (minimum that need to sign)
 *
 * 4. Hash of the previous TrustContent
 *
 * 5. Signature by an hsm
 * </p>
 * <pre>
 * -----------------------------------------------------------------
 * |_________________________Trust_________________________________|
 * |Identifier|PublicKey1| ... |PublicKey_n|Quorum|Predecessor Hash|
 * |__________|__________|_____|___________|______|________________|
 *</pre>
 */
public class TrustContent implements Serializable {

    /**
     * Unique identifier to this trustContent
     */
    private final int identifier;
    private static int trustCounter = 0;
    /**
     * A list of the hsm public keys
     */
    private final List<PublicKey> hsmPublicKeys;
    /**
     * A list of the operators public keys
     */
    private final List<PublicKey> operatorPublicKeys;
    /**
     * the min. value of operators to assess a trustContent
     */
    private final int quorumMinValue;

    /**
     * Hash of previous trustContent
     */
    private byte[] predecessorHash;

    /**
     * TrustContent constructor
     */
    public TrustContent(List<PublicKey> hsmPublicKeys, List<PublicKey> operatorPublicKeys, byte[] predecessorHash) {
        this.identifier = ++trustCounter;
        this.hsmPublicKeys = new ArrayList<>(hsmPublicKeys);
        if(operatorPublicKeys == null) {
            this.operatorPublicKeys = new ArrayList<>();
            this.quorumMinValue = 0;
        }
        else {
            this.operatorPublicKeys = new ArrayList<>(operatorPublicKeys);
            this.quorumMinValue = operatorPublicKeys.size();
        }

        this.predecessorHash = predecessorHash.clone();
    }

    private TrustContent(TrustContent trustContent) {
        this.hsmPublicKeys = new ArrayList<>(trustContent.getHsmPublicKeys());
        this.operatorPublicKeys = new ArrayList<>(trustContent.getOperatorPublicKeys());
        this.identifier = trustContent.getId();
        this.quorumMinValue = trustContent.getQuorumMinValue();
        this.predecessorHash = trustContent.getPredecessorHash().clone();
    }

    /**
     * Check if a given hsm public key exists in the trustContent
     * @param publicKey the public key that we want to look for
     * @return true if given public key exists in trustContent
     */
    public boolean checkExistHardwarePublicKey(PublicKey publicKey) {
        return hsmPublicKeys.contains(publicKey);
    }

    /**
     * Check if a given operator public key exists in the trustContent
     * @param publicKey the public key that we want to look for
     * @return true if given public key exists in trustContent
     */
    public boolean checkExistOperatorPublicKey(PublicKey publicKey) {
        return operatorPublicKeys.contains(publicKey);
    }

    /**
     * Set predecessor hash for the trustContent
     * @param hash the previous trustContent hash
     */
    public void setPredecessorHash(byte[] hash) {
        this.predecessorHash = hash;
    }

    public List<PublicKey> getHsmPublicKeys() {
        return this.hsmPublicKeys;
    }

    public List<PublicKey> getOperatorPublicKeys() {
        return this.operatorPublicKeys;
    }

    public int getQuorumMinValue() {
        return quorumMinValue;
    }

    public int getId() {
        return identifier;
    }

    public byte[] getPredecessorHash() {
        return predecessorHash;
    }


    public TrustContent clone() {
        return new TrustContent(this);
    }
}
