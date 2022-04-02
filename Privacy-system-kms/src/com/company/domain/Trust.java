package com.company.domain;

import java.util.LinkedList;
import java.util.Map;
import java.security.PublicKey;
import java.security.Signature;
public class Trust {
    private String domain_identifier;
    private Map<String,PublicKey> domain_public_keys;
    private Quorum quorum;
    private String previous_hash;
    private LinkedList<Signature> domain_signatures;


    // ---------------------------------------------------------------------

    public Trust() {

    }

    // ---------------------------------------------------------------------


    public String getDomainIdentifier() {
        return domain_identifier;
    }

    public void setDomainIdentifier(String domain_identifier) {
        this.domain_identifier = domain_identifier;
    }

    public Map<String, PublicKey> getDomainPublicKeys() {
        return domain_public_keys;
    }

    public void setDomainPublicKeys(Map<String, PublicKey> domain_public_keys) {
        this.domain_public_keys = domain_public_keys;
    }

    public Quorum getQuorum() {
        return quorum;
    }

    public void setQuorum(Quorum quorum) {
        this.quorum = quorum;
    }

    public String getPreviousHash() {
        return previous_hash;
    }

    public void setPreviousHash(String previous_hash) {
        this.previous_hash = previous_hash;
    }

    public LinkedList<Signature> getDomainSignatures() {
        return domain_signatures;
    }

    public void setDomainSignatures(LinkedList<Signature> domain_signatures) {
        this.domain_signatures = domain_signatures;
    }
}
