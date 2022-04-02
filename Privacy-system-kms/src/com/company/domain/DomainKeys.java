package com.company.domain;

import java.util.LinkedList;

public class DomainKeys {
    private String token;                       // cipher master key
    private LinkedList<String> domain_keys;     // public keys that can decrypt master key


    // ---------------------------------------------------------------------

    public DomainKeys(String token, LinkedList<String> domain_keys) {
        this.token = token;
        this.domain_keys = domain_keys;
    }

    // ---------------------------------------------------------------------

    public String getToken() {
        return token;
    }


    public LinkedList<String> getDomainKeys() {
        return domain_keys;
    }

}
