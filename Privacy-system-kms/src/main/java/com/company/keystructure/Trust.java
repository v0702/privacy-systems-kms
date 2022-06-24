package com.company.keystructure;

import com.company.GeneralManager;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Base64;

import static com.company.utility.CryptographyOperations.getHashIdentifier;

/**
 * <pre>
 * ---------------------------------------------------------------------------
 * |_________________________Trust___________________________________________|
 * |                      TrustContent                             |Signature|
 * |_______________________________________________________________|_________|
 * |Identifier|PublicKey1| ... |PublicKey_n|Quorum|Predecessor Hash|
 * |__________|__________|_____|___________|______|________________|
 * </pre>
 */
public class Trust implements Serializable {

    private final TrustContent trustContent;
    private GeneralSignature signature;

    public Trust(TrustContent trustContent, GeneralSignature signature) {
        this.trustContent = trustContent;
        this.signature = signature;
    }

    public Trust(Trust trust) {
        this.trustContent = trust.getTrustContent().clone();
        this.signature = trust.getSignature().clone();
    }

    public void setSignature(GeneralSignature signature) {
        this.signature = signature;
    }

    @Override
    public String toString() {
        StringBuilder strBuilder = new StringBuilder();
        PublicKey pk;

        strBuilder.append("Trust ID: ").append(trustContent.getId()).append("\n");

        strBuilder.append("---------------HSM public keys--------------\n");
        for (int i=0;i< trustContent.getHsmPublicKeys().size();++i) {
            pk = trustContent.getHsmPublicKeys().get(i);
            if(GeneralManager.HIGH_VERBOSE)
                strBuilder.append(i).append(". ").append(Base64.getEncoder().encodeToString(pk.getEncoded())).append("\n");
            else
                strBuilder.append(i).append(". ").append(getHashIdentifier(pk)).append("\n");
        }
        strBuilder.append("--------------------------------------------\n");

        strBuilder.append("--------------OperatorTemp public keys---------------\n");
        for (int i=0;i< trustContent.getOperatorPublicKeys().size();++i) {
            pk = trustContent.getOperatorPublicKeys().get(i);
            if(GeneralManager.HIGH_VERBOSE)
                strBuilder.append(i).append(". ").append(Base64.getEncoder().encodeToString(pk.getEncoded())).append("\n");
            else
                strBuilder.append(i).append(". ").append(getHashIdentifier(pk)).append("\n");
        }
        strBuilder.append("-------------------------------------------------\n");

        strBuilder.append("-Quorum value: ").append(trustContent.getQuorumMinValue()).append("\n");
        if(signature != null) {
            if(GeneralManager.HIGH_VERBOSE) {
                strBuilder.append("-Signature: ").append(Base64.getEncoder().encodeToString(signature.signature())).append("\n");
                strBuilder.append("-Signature public key: ").append(Base64.getEncoder().encodeToString(signature.publicKey().getEncoded())).append("\n");
            }
            else {
                strBuilder.append("-Signature: ").append(getHashIdentifier(signature.signature())).append("\n");
                strBuilder.append("-Signature public key: ").append(getHashIdentifier(signature.publicKey())).append("\n");
            }
        }
        else
            strBuilder.append("-No signature\n");

        return strBuilder.toString();
    }

    /**
     * get the TrustContent class in the trust
     * with contents such as an ID, public keys etc.
     * @return object of TrustContent
     */
    public TrustContent getTrustContent() {
        return trustContent;
    }

    /**
     * Get the signature of the trust
     * In this case the signature signs over the
     * TrustContent object
     * @return object of GeneralSignature
     */
    public GeneralSignature getSignature() {
        return signature;
    }

    public Trust clone() {
        return new Trust(this);
    }
}
