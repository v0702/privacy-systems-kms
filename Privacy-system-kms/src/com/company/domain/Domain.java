package com.company.domain;

import java.security.PublicKey;
import java.security.Signature;
import java.util.LinkedList;

public class Domain {
    private LinkedList<PublicKey> trust;
    private DomainKeys domain_keys;
    private LinkedList<Signature> domain_signatures;

    // ---------------------------------------------------------------------

    // TODO: change this to a real Trust object
    public Domain(LinkedList<PublicKey> domain_public_keys, DomainKeys domain_keys, LinkedList<Signature> domain_signatures) {
        this.trust = domain_public_keys;
        this.domain_keys = domain_keys;
        this.domain_signatures = domain_signatures;
    }

    // ---------------------------------------------------------------------


    public LinkedList<PublicKey> getTrust() {
        return trust;
    }

    public DomainKeys getDomainKeys() {
        return domain_keys;
    }

    public LinkedList<Signature> getDomainSignatures() {
        return domain_signatures;
    }
}
