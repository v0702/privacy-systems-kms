package com.company.utility;

import com.company.hsm.HardwareSecurityModule;
import com.company.keystructure.*;
import com.company.utility.CryptographyOperations;
import de.vandermeer.asciitable.AT_Row;
import de.vandermeer.asciitable.AsciiTable;
import de.vandermeer.skb.interfaces.transformers.textformat.TextAlignment;

import java.security.PublicKey;
import java.util.*;

import static com.company.utility.CryptographyOperations.getHashIdentifier;

public class GeneralManager {

    /*----------------------------------Variables and constructor----------------------------------*/

    /**
     * The public keys of the hsm in service
     */
    List<PublicKey> hsmServicePublicKeysList;
    /**
     * The operator public keys in service
     */
    List<PublicKey> operatorServicePublicKeysList;

    /**
     * TODO: Operator domain hash signature?
     */
    List<String> operatorIdentifierList;

    /**
     * List of domains
     */
    List<Domain> domainsList;

    /**
     * List of signed trusts
     */
    List<Trust> trustList;
    /**
     * List of unsigned trust list
     */
    List<Trust> unsignedTrustList;

    /**
     * List of hardware security module
     */
    List<HardwareSecurityModule> hsmList;

    /**
     * List of operator signature of trust
     */
    List<OperatorSignature> operatorsTrustSignatureList;
    List<OperatorSignature> operatorsTrustSignatureListLogging;

    /**
     * hsm number id counter
     */
    int hsmIdCounter;
    /**
     * domain number id counter
     */
    int domainIdCounter;

    public static boolean HIGH_VERBOSE = false;

    /**
     * Types of trusts, signed or unsigned
     */
    public enum TRUST_LIST_TYPE {
        SIGNED,
        UNSIGNED
    }

    Random random;

    /*---------------------------------------------------------------------------------------------*/
    /*------------------------------------------Constructor----------------------------------------*/

    /**
     * Create a general manager.
     * Creates 1 start hsm and a start trust.
     */
    public GeneralManager(int startHsmAmount) {
        random = new Random();
        hsmServicePublicKeysList = new ArrayList<>();
        operatorServicePublicKeysList = new ArrayList<>();
        operatorsTrustSignatureList = new ArrayList<>();
        operatorsTrustSignatureListLogging = new ArrayList<>();
        operatorIdentifierList = new ArrayList<>();
        domainsList = new ArrayList<>();
        trustList = new ArrayList<>();
        unsignedTrustList = new ArrayList<>();
        hsmList = new ArrayList<>();
        hsmIdCounter = 0;
        domainIdCounter = 0;

        // add start hsm
        for(int i=0;i<startHsmAmount;++i)
            createNewHardwareSecurityModule();
    }

    public GeneralManager() {
        this(5);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------General operations-------------------------------------*/

    /**
     * <p>Add a new hsm to the system</p>
     * <p>Hsm created used RSA</p>
     * <p>Adds public key from new hsm to hsmServicePublicKeyList</p>
     * <p>HsmIdCounter is incremented</p>
     */
    public void createNewHardwareSecurityModule() {
        try {
            HardwareSecurityModule newHsm = new HardwareSecurityModule(hsmIdCounter++, CryptographyOperations.RSA_KEY_LENGTH_2, CryptographyOperations.KEY_GENERATOR_ALGORITHM_RSA);
            hsmList.add(newHsm);
            hsmServicePublicKeysList.add(newHsm.getPublicKey());
        }
        catch (IllegalArgumentException ie) {
            System.out.println("Wrong algorithm description: " + ie.getMessage());
        }
        catch (Exception e) {
            System.out.println("General exception(?): " + e.getMessage());
        }
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Trust operations--------------------------------------*/

    public void createFirstDayTrust() {
        //get first hsm
        HardwareSecurityModule hsm = getHsmById(0);
        if (hsm == null)
            return;

        // create trust with all public keys from available hsm and no operator public keys
        Trust trust = hsm.createTrust(hsmServicePublicKeysList, new ArrayList<>());
        hsm.signNewTrust(trust);
        trustList.add(trust);
    }

    /**
     * Create a new trust, not signed
     * @param hmsIdsList a list of the hsms to add to the trust
     */
    public void createUnsignedTrust(List<Integer> hmsIdsList, List<Integer> operatorPublicKeyIndexList) {
        //get random hsm from hsm id list given
        int workerHsmId = hmsIdsList.get(random.nextInt(hmsIdsList.size()));

        //check if given id is valid
        if (hsmIdCounter <= workerHsmId) {
            System.out.println("hsmId not valid -> hsm id given:"+ workerHsmId +" hsm counter: "+ hsmIdCounter);
            return;
        }

        //get chosen hsm
        HardwareSecurityModule hsm = getHsmById(workerHsmId);
        if (hsm == null) {
            System.out.println("Given hsm id not valid.");
            return;
        }

        //process to get a random set of operators on a trust if it is empty
        List<PublicKey> operatorPublicKeyList = new ArrayList<>();
        if(operatorPublicKeyIndexList.isEmpty()) {
            int numberOfOperatorPublicKeys = operatorServicePublicKeysList.size();
            int halfOperatorPublicKeys = (numberOfOperatorPublicKeys/2 > 0) ? numberOfOperatorPublicKeys/2 : 1;

            Collections.shuffle(operatorServicePublicKeysList);
            for(int i=0;i<halfOperatorPublicKeys;i++)
                operatorPublicKeyList.add(operatorServicePublicKeysList.get(i));
        }
        else {
            for(int index : operatorPublicKeyIndexList)
                operatorPublicKeyList.add(getOperatorPublicKeyById(index));
        }

        //get the public keys from the given hsm id list
        List<PublicKey> hsmPublicKeyList = new ArrayList<>();
        for (Integer hsmId : hmsIdsList) {
            hsmPublicKeyList.add(getHsmById(hsmId).getPublicKey());
        }

        Trust unsignedTrust = hsm.createTrust( new ArrayList<>(hsmPublicKeyList), new ArrayList<>(operatorPublicKeyList));
        unsignedTrustList.add(unsignedTrust);
    }

    /**
     * <p>Operator sign a trust with his domain key pair</p>
     * <p>If operator already signed the trust the old signature is removed and a new one is created</p>
     * @param trustId the id of the trust to sign
     * @param domainId the id of the domain to unwrap and use the key to sign
     * @return true if success else false
     */
    public boolean operatorSignTrust(int trustId, int domainId) {

        //get trust and domain by id
        Trust unsignedTrust = getTrustById(trustId, TRUST_LIST_TYPE.UNSIGNED);
        Domain domain = getDomainById(domainId);

        //verify if signature already exists
        //checks if signature is for the same trust and if the domain being used is the same (same person)
        List<OperatorSignature> trustSignatureList = getOperatorTrustSignatureByTrustId(trustId);
        for(OperatorSignature operatorSignature : trustSignatureList) {
            if(operatorSignature.generalSignature().publicKey().equals(domain.domainContent().domainKeys().masterKeyToken().publicKey()))
                operatorsTrustSignatureList.remove(operatorSignature);
        }

        //get free hsm that belongs in trust (in this case its just random)
        List<PublicKey> trustHsmPublicKeys = unsignedTrust.getTrustContent().getHsmPublicKeys();
        HardwareSecurityModule hsm = getHsmByPublicKey(trustHsmPublicKeys.get(random.nextInt(trustHsmPublicKeys.size())));
        if(hsm == null) {
            System.out.println(">HSM not found.");
            return false;
        }

        //get hash of trust content
        byte[] hash = hsm.hashSum(CryptographyOperations.objectToByte(unsignedTrust.getTrustContent()), CryptographyOperations.HASH_ALGORITHM_1);
        if(hash == null) {
            System.out.println(">Hash not created.");
            return false;
        }

        //sign the hash with domain, by unwrapping the master key and using the private key
        GeneralSignature generalSignature = hsm.signWithDomain(hash, domain);
        if(generalSignature == null) {
            System.out.println(">Signature failure.");
            return false;
        }

        operatorsTrustSignatureList.add(new OperatorSignature(generalSignature, trustId));

        return true;
    }

    /**
     * Sign a trust by giving an id of the desired trust to sign
     * @param trustId the id of the trust to sign
     */
    public void signTrust(int trustId) {
        Trust trust = getTrustById(trustId, TRUST_LIST_TYPE.UNSIGNED);
        if(trust == null) {
            return;
        }

        List<OperatorSignature> operatorSignatureSubList = getOperatorTrustSignatureByTrustId(trustId);

        //get free hsm that belongs in trust (in this case its just random)
        List<PublicKey> trustHsmPublicKeys = trust.getTrustContent().getHsmPublicKeys();
        HardwareSecurityModule hsm = getHsmByPublicKey(trustHsmPublicKeys.get(random.nextInt(trustHsmPublicKeys.size())));

        boolean signatureSuccess = hsm.signTrust(trust,operatorSignatureSubList);
        if (signatureSuccess) {
            trustList.add(trust);
            unsignedTrustList.remove(trust);

            operatorsTrustSignatureListLogging.addAll(operatorSignatureSubList);
            operatorsTrustSignatureList.removeAll(operatorSignatureSubList);
            System.out.println("Success in signing trust.");
        }
        else
            System.out.println("Failure signing trust.");
    }

    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------Domain operations--------------------------------------*/

    /**
     * Create a domain from a trust
     * @param trustId id of trust to be used for domain creating
     */
    public int createDomain(int trustId, HardwareSecurityModule.DOMAIN_KEYS_TYPE domainKeysType) {
        Trust trust = getTrustById(trustId, TRUST_LIST_TYPE.SIGNED);
        if (trust == null) {
            System.out.println("Trust " + trustId + " not found.");
            return -1;
        }

        //get free hsm that belongs in trust (in this case its just random)
        List<PublicKey> trustHsmPublicKeys = trust.getTrustContent().getHsmPublicKeys();
        HardwareSecurityModule hsm = getHsmByPublicKey(trustHsmPublicKeys.get(random.nextInt(trustHsmPublicKeys.size())));

        Domain newDomain = hsm.createDomain(trust, domainKeysType, ++domainIdCounter);

        if (newDomain == null)
            System.out.println("Failure creating domain, signature failed.");
        else if(domainKeysType == HardwareSecurityModule.DOMAIN_KEYS_TYPE.ASYMMETRIC_KEY_DOMAIN) {
            operatorServicePublicKeysList.add(newDomain.domainContent().domainKeys().masterKeyToken().publicKey());
            operatorIdentifierList.add(getHashIdentifier(newDomain));
        }
        domainsList.add(newDomain);

        return domainIdCounter;
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-----------------------------------Signature verification------------------------------------*/

    /**
     * Gets domain from id and checks is signature validity
     * @param domainId the id of domain to verify
     * @return true if domain is valid else false
     */
    public boolean verifyDomainSignature(int domainId) {
        HardwareSecurityModule hsm = hsmList.get(random.nextInt(hsmList.size()));
        return hsm.verifyDomainSignature(getDomainById(domainId));
    }

    /**
     * Gets trust from id and checks is signature validity
     * @param trustId the id of trust to verify
     * @return true if trust is valid else false
     */
    public boolean verifyTrustSignature(int trustId) {
        HardwareSecurityModule hsm = hsmList.get(random.nextInt(hsmList.size()));
        return hsm.verifyTrustSignature(getTrustById(trustId, TRUST_LIST_TYPE.SIGNED));
    }

    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------Client operations--------------------------------------*/

    public byte[] encryptWithDomain(byte[] data, int domainId) {
        Domain domain = getDomainById(domainId);
        Trust trust = domain.domainContent().trust();

        //get free hsm that belongs in trust (in this case its just random)
        List<PublicKey> trustHsmPublicKeys = trust.getTrustContent().getHsmPublicKeys();
        HardwareSecurityModule hsm = getHsmByPublicKey(trustHsmPublicKeys.get(random.nextInt(trustHsmPublicKeys.size())));

        byte[] encryptedData = hsm.encryptWithDomain(data, domain);
        return Objects.requireNonNullElseGet(encryptedData, () -> new byte[0]);
    }

    public byte[] decryptWithDomain(byte[] encryptedData, int domainId) {
        Domain domain = getDomainById(domainId);
        Trust trust = domain.domainContent().trust();

        //get free hsm that belongs in trust (in this case its just random)
        List<PublicKey> trustHsmPublicKeys = trust.getTrustContent().getHsmPublicKeys();
        HardwareSecurityModule hsm = getHsmByPublicKey(trustHsmPublicKeys.get(random.nextInt(trustHsmPublicKeys.size())));

        byte[] data = hsm.decryptWithDomain(encryptedData, domain);
        return Objects.requireNonNullElseGet(data, () -> new byte[0]);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-------------------------------------------Getters-------------------------------------------*/

    public PublicKey getOperatorPublicKeyById(int index) {
        return operatorServicePublicKeysList.get(index);
    }

    /**
     * Get a hsm by its public key
     * @param publicKey the public key of the hsm to get
     * @return The hsm found or null if not
     */
    public HardwareSecurityModule getHsmByPublicKey(PublicKey publicKey) {
        for(HardwareSecurityModule hsm : hsmList) {
            if(hsm.getPublicKey().equals(publicKey))
                return hsm;
        }
        return null;
    }

    /**
     * Gets a sub list of the operators trust signature
     * @param trustId the trust id of the trust signatures that we want
     * @return a sub list of the operator's signature of a specified trust
     */
    public List<OperatorSignature> getOperatorTrustSignatureByTrustId(int trustId) {
        List<OperatorSignature> operatorTrustSignaturesSubList = new ArrayList<>();

        for (OperatorSignature operatorTrustSignature : operatorsTrustSignatureList) {
            if (operatorTrustSignature.idOfTrust() == trustId)
                operatorTrustSignaturesSubList.add(operatorTrustSignature);
        }
        return operatorTrustSignaturesSubList;
    }

    /**
     * Gets an hsm from a given int id
     * @param id int id to identify hsm
     * @return the hsm with the pretended id or null if not found
     */
    public HardwareSecurityModule getHsmById(int id) {
        for (HardwareSecurityModule hsm : hsmList) {
            if(hsm.getId() == id)
                return hsm;
        }
        return null;
    }

    /**
     * Gets a trust from a given int id
     * @param id int id to identify trust
     * @param type the type of trust list we want to check
     *             signed or unsigned
     * @return the trust with the pretended id or null if not found
     */
    public Trust getTrustById(int id, TRUST_LIST_TYPE type) {

        switch (type) {
            case SIGNED -> {
                for (Trust trust : trustList) {
                    if(trust.getTrustContent().getId() == id)
                        return trust;
                }
            }
            case UNSIGNED -> {
                for (Trust trust : unsignedTrustList) {
                    if(trust.getTrustContent().getId() == id)
                        return trust;
                }
            }
            default -> {
                return null;
            }
        }
        return null;
    }

    /**
     * Get a domain from a given int id
     * @param domainId int id that identifies the domain
     * @return the domain or null if not found
     */
    public Domain getDomainById(int domainId) {
        for(Domain domain : domainsList) {
            if(domain.domainId() == domainId)
                return domain;
        }
        return null;
    }

    /**
     * Get asymmetric domain from its master key par public key
     * @param publicKey the public key to find the domain it belongs to
     * @return the domain or null if not found
     */
    public Domain getDomainByPublicKey(PublicKey publicKey) {
        for (Domain domain : domainsList) {
            PublicKey tempPublicKey = domain.domainContent().domainKeys().masterKeyToken().publicKey();
            if (publicKey.equals(tempPublicKey))
                return domain;
        }
        return null;
    }

    public boolean checkDomainExist(int domainId) {
        return getDomainById(domainId) != null;
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Show information--------------------------------------*/

    public String showTrusts(int domainId, TRUST_LIST_TYPE type) {
        StringBuilder stringBuilder = new StringBuilder();
        PublicKey operatorPublicKey = getDomainById(domainId).domainContent().domainKeys().masterKeyToken().publicKey();
        boolean trustContainsOperator = false;

        List<Trust> trustListToShow = null;

        switch (type) {
            case SIGNED -> trustListToShow = trustList;
            case UNSIGNED -> trustListToShow = unsignedTrustList;
        }
        if(trustListToShow == null)
            return "";

        for (Trust trust : trustListToShow) {
            AsciiTable at = new AsciiTable();

            TrustContent trustContent = trust.getTrustContent();

            at.addRule();
            AT_Row row;

            List<PublicKey> trustHsmPublicKeysList = trustContent.getHsmPublicKeys();
            List<PublicKey> trustOperatorPublicKeysList = trustContent.getOperatorPublicKeys();

            List<String> header = new ArrayList<>();
            List<String> content = new ArrayList<>();

            header.add("Trust identifier");
            content.add(String.valueOf(trustContent.getId()));

            for (PublicKey publicKey : trustHsmPublicKeysList) {
                header.add("Hsm public key");
                content.add(CryptographyOperations.getHashIdentifier(publicKey));
            }
            for (PublicKey publicKey : trustOperatorPublicKeysList) {
                if(publicKey.equals(operatorPublicKey))
                    trustContainsOperator = true;
                header.add("Operator public key");
                content.add(CryptographyOperations.getHashIdentifier(publicKey));
            }
            header.add("Trust signature");
            if (trust.getSignature() == null)
                content.add("No signature");
            else
                content.add(trust.getSignature().getSignatureHash());
            header.add("Quorum");
            content.add(String.valueOf(trustContent.getQuorumMinValue()));
            header.add("Predecessor hash");
            content.add(" ");


            row = at.addRow(header);
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();

            row = at.addRow(content);
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();

            stringBuilder.append(at.render()).append("\n");
        }
        return stringBuilder.toString();
    }

    public String showTrustById(int trustId) {
        StringBuilder stringBuilder = new StringBuilder();
        AsciiTable at = new AsciiTable();

        Trust trust = getTrustById(trustId, TRUST_LIST_TYPE.SIGNED);
        if(trust == null)
            return "Trust not found";

        TrustContent trustContent = trust.getTrustContent();

        at.addRule();
        AT_Row row;

        List<PublicKey> trustHsmPublicKeysList = trustContent.getHsmPublicKeys();
        List<PublicKey> trustOperatorPublicKeysList = trustContent.getOperatorPublicKeys();

        List<String> header = new ArrayList<>();
        List<String> content = new ArrayList<>();

        header.add("Trust identifier");
        content.add(String.valueOf(trustContent.getId()));

        for (PublicKey publicKey : trustHsmPublicKeysList) {
            header.add("Hsm public key");
            content.add(CryptographyOperations.getHashIdentifier(publicKey));
        }
        for (PublicKey publicKey : trustOperatorPublicKeysList) {
            header.add("Operator public key");
            content.add(CryptographyOperations.getHashIdentifier(publicKey));
        }
        header.add("Trust signature");
        if (trust.getSignature() == null)
            content.add("No signature");
        else
            content.add(trust.getSignature().getSignatureHash());
        header.add("Quorum");
        content.add(String.valueOf(trustContent.getQuorumMinValue()));
        header.add("Predecessor hash");
        content.add(" ");


        row = at.addRow(header);
        row.setTextAlignment(TextAlignment.CENTER);
        at.addRule();

        row = at.addRow(content);
        row.setTextAlignment(TextAlignment.CENTER);
        at.addRule();

        stringBuilder.append(at.render()).append("\n");

        return stringBuilder.toString();
    }

    public String showDomains() {
        StringBuilder stringBuilder = new StringBuilder();

        for (Domain domain : domainsList) {
            AsciiTable at = new AsciiTable();

            DomainContent domainContent = domain.domainContent();
            Trust trust = domainContent.trust();
            GeneralSignature domainSignature = domain.signature();

            at.addRule();
            AT_Row row;

            List<String> header = new ArrayList<>();
            List<String> content = new ArrayList<>();

            stringBuilder.append(">Domain:\n");
            header.add("domain identifier");
            content.add(String.valueOf(domain.domainId()));

            List<Token> wrapKeyTokenList = domainContent.domainKeys().wrapKeyTokenList();

            for (Token token : wrapKeyTokenList) {
                header.add("Wrap key token");
                content.add(CryptographyOperations.getHashIdentifier(token.encryptedKey()));
            }

            header.add("Master key token");
            content.add(CryptographyOperations.getHashIdentifier(domainContent.domainKeys().masterKeyToken().encryptedKey()));

            PublicKey publicKey = domainContent.domainKeys().masterKeyToken().publicKey();
            if (publicKey != null) {
                header.add("master key pair public key");
                content.add(getHashIdentifier(publicKey));
            }

            header.add("Domain signature");
            if (trust.getSignature() == null)
                content.add("No signature");
            else
                content.add(domainSignature.getSignatureHash());


            row = at.addRow(header);
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();

            row = at.addRow(content);
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();

            stringBuilder.append(at.render()).append("\n>Trust:\n").append(showTrustById(trust.getTrustContent().getId())).append("\n");
        }

        return stringBuilder.toString();
    }

    public String showDomain(int domainId) {
        StringBuilder stringBuilder = new StringBuilder();
        AsciiTable at = new AsciiTable();

        Domain domain = getDomainById(domainId);
        DomainContent domainContent = domain.domainContent();

        Trust trust = domainContent.trust();
        GeneralSignature domainSignature = domain.signature();

        at.addRule();
        AT_Row row;

        List<String> header = new ArrayList<>();
        List<String> content = new ArrayList<>();

        stringBuilder.append(">Domain:\n");
        header.add("domain identifier");
        content.add(String.valueOf(domain.domainId()));

        List<Token> wrapKeyTokenList = domainContent.domainKeys().wrapKeyTokenList();

        for (Token token : wrapKeyTokenList) {
            header.add("Wrap key token");
            content.add(CryptographyOperations.getHashIdentifier(token.encryptedKey()));
        }

        header.add("Master key token");
        content.add(CryptographyOperations.getHashIdentifier(domainContent.domainKeys().masterKeyToken().encryptedKey()));

        PublicKey publicKey = domainContent.domainKeys().masterKeyToken().publicKey();
        if(publicKey != null) {
            header.add("master key pair public key");
            content.add(getHashIdentifier(publicKey));
        }

        header.add("Domain signature");
        if (trust.getSignature() == null)
            content.add("No signature");
        else
            content.add(domainSignature.getSignatureHash());


        row = at.addRow(header);
        row.setTextAlignment(TextAlignment.CENTER);
        at.addRule();

        row = at.addRow(content);
        row.setTextAlignment(TextAlignment.CENTER);
        at.addRule();

        stringBuilder.append(at.render()).append("\n>Trust:\n").append(showTrustById(trust.getTrustContent().getId())).append("\n");

        return stringBuilder.toString();
    }

    public String showOperatorTrustSignatures(int trustId) {
        StringBuilder stringBuilder = new StringBuilder();

        List<OperatorSignature> operatorSignaturesSubList = getOperatorTrustSignatureByTrustId(trustId);

        stringBuilder.append("Operator signature for trust: ").append(trustId)
                     .append("\nNumber of signatures: ").append(operatorSignaturesSubList.size()).append("\n");

        for(OperatorSignature operatorSignature : operatorSignaturesSubList) {
            AsciiTable at = new AsciiTable();
            at.addRule();
            AT_Row row;

            row = at.addRow("Signature");
            row = at.addRow(operatorSignature.generalSignature().getSignatureHash());
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();

            row = at.addRow("Public key");
            row = at.addRow(operatorSignature.generalSignature().getPublicKeyHash());
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();

            stringBuilder.append(at.render()).append("\n");
        }
        return stringBuilder.toString();
    }

    public String showOperatorPublicKeys() {
        StringBuilder stringBuilder = new StringBuilder();
        AsciiTable at = new AsciiTable();

        at.addRule();
        AT_Row row;

        List<String> header = new ArrayList<>();
        List<String> content = new ArrayList<>();

        header.add("Index");
        header.add("Operator public keys");

        row = at.addRow(header);
        row.setTextAlignment(TextAlignment.CENTER);
        at.addRule();

        for (int i=0;i<operatorServicePublicKeysList.size();++i) {
            PublicKey publicKey = operatorServicePublicKeysList.get(i);
            content.clear();
            content.add(String.valueOf(i));
            content.add(CryptographyOperations.getHashIdentifier(publicKey));

            row = at.addRow(content);
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();
        }

        stringBuilder.append(at.render()).append("\n");

        return stringBuilder.toString();
    }

    public String showHsmPublicKeys() {
        StringBuilder stringBuilder = new StringBuilder();
        AsciiTable at = new AsciiTable();

        at.addRule();
        AT_Row row;

        row = at.addRow("Hsm public keys");
        row.setTextAlignment(TextAlignment.CENTER);
        at.addRule();

        for (PublicKey publicKey : hsmServicePublicKeysList) {
            row = at.addRow(CryptographyOperations.getHashIdentifier(publicKey));
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();
        }

        stringBuilder.append(at.render()).append("\n");

        return stringBuilder.toString();
    }

    public String showHsm() {
        StringBuilder stringBuilder = new StringBuilder();
        AsciiTable at = new AsciiTable();
        at.addRule();
        AT_Row row;

        List<String> header = new ArrayList<>();
        List<String> content = new ArrayList<>();

        header.add("Identifier");
        header.add("public key");

        row = at.addRow(header);
        row.setTextAlignment(TextAlignment.CENTER);
        at.addRule();

        for (HardwareSecurityModule hsm : hsmList) {
            content.clear();
            content.add(String.valueOf(hsm.getId()));
            content.add(CryptographyOperations.getHashIdentifier(hsm.getPublicKey()));

            row = at.addRow(content);
            row.setTextAlignment(TextAlignment.CENTER);
            at.addRule();

        }
        stringBuilder.append(at.render()).append("\n");

        return stringBuilder.toString();
    }

    /*---------------------------------------------------------------------------------------------*/
}