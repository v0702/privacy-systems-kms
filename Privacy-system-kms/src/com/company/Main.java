package com.company;

import com.company.components.Hsm;
import com.company.domain.Domain;
import com.company.domain.DomainKeys;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.LinkedList;

public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        LinkedList<Signature> signatures = null;
        LinkedList<PublicKey> pub_keys = new LinkedList<>();

        Hsm hsmA = new Hsm();
        Hsm hsmB = new Hsm();
        Hsm hsmC = new Hsm();

        pub_keys.add(hsmA.getPubKey());
        pub_keys.add(hsmB.getPubKey());
        pub_keys.add(hsmC.getPubKey());

        DomainKeys domain_keys_A = hsmA.generateDomainKeys(pub_keys);
        Domain domain_A = new Domain(pub_keys, domain_keys_A, signatures);

        DomainKeys domain_keys_B = hsmB.generateDomainKeys(pub_keys);
        Domain domain_B = new Domain(pub_keys, domain_keys_B, signatures);

        DomainKeys domain_keys_C = hsmA.generateDomainKeys(pub_keys);
        Domain domain_C = new Domain(pub_keys, domain_keys_C, signatures);

        LinkedList<Domain> domains = new LinkedList<>();
        domains.add(domain_A);
        domains.add(domain_B);
        domains.add(domain_C);



    }
}
