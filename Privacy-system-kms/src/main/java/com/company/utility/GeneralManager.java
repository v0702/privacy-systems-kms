package com.company.utility;

import com.company.hsm.HardwareSecurityModule;
import com.company.keystructure.*;

import de.vandermeer.asciitable.AT_Row;
import de.vandermeer.asciitable.AsciiTable;
import de.vandermeer.skb.interfaces.transformers.textformat.TextAlignment;

import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import static com.company.utility.CryptographyOperations.getHashIdentifier;
public class GeneralManager {

    /*----------------Connecting Clients----------------*/

    private static List<String> operatorClientList;

    private static List<String> clientClientList;

    /*--------------------------------------------------*/
    /*---------------------Operator---------------------*/

    /**
     * The operator public keys, associated with operator name.
     */
    HashMap<String, PublicKey> operatorNameAndPublicKeyList;

    /**
     * The operator public keys list.
     */
    List<PublicKey> operatorPublicKeysList;

    /*--------------------------------------------------*/
    /*------------------------HSM-----------------------*/

    /**
     * Types of trusts, signed or unsigned
     */
    public enum TRUST_LIST_TYPE {
        SIGNED,
        UNSIGNED
    }

    /**
     * hsm number id counter
     */
    int hsmIdCounter;

    /**
     * List of hardware security modules.
     */
    List<HardwareSecurityModule> hsmList;

    /**
     * The public keys of the hsm in service.
     */
    List<PublicKey> hsmServicePublicKeysList;

    /*--------------------------------------------------*/
    /*-----------------Data structures------------------*/

    /**
     * domain number id counter
     */
    int domainIdCounter;

    /**
     * List of domains.
     */
    List<Domain> domainsList;

    /**
     * List of signed trusts.
     */
    List<Trust> trustList;

    /**
     * List of unsigned trusts.
     */
    List<Trust> unsignedTrustList;

    /**
     * List of operator signature of trust
     */
    List<OperatorSignature> operatorsTrustSignatureList;
    List<OperatorSignature> operatorsTrustSignatureListLogging;

    /*--------------------------------------------------*/

    public static boolean HIGH_VERBOSE = false;

    Random random;

    /*---------------------------------------------------------------------------------------------*/
    /*------------------------------------------Constructor----------------------------------------*/

    /**
     * Create a general manager.
     * Creates 1 start hsm.
     */
    public GeneralManager(int startHsmAmount) {
        random = new Random();

        operatorNameAndPublicKeyList = new HashMap<>();

        hsmServicePublicKeysList = new ArrayList<>();
        operatorsTrustSignatureList = new ArrayList<>();
        operatorPublicKeysList = new ArrayList<>();
        operatorsTrustSignatureListLogging = new ArrayList<>();
        operatorClientList = new ArrayList<>();
        clientClientList = new ArrayList<>();
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

    /**
     * Create a general manager, Create 5 start hsm.
     */
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
            System.err.println("Wrong algorithm description: " + ie.getMessage());
        }
        catch (Exception e) {
            System.err.println("General exception(?): " + e.getMessage());
        }
    }

    /**
     * Generate a RSA key pair, using an HSM in the network.
     * @return a RSA keyPair.
     */
    public KeyPair generateKeyPairWithHSM() {
        return getRandomHSM().generateKeyPair();
    }

    /**
     *  Register and operator name and operator public key, in a hash map, using operator as key.
     * @param operatorName operator name.
     * @param operatorPublicKey operator public key.
     */
    public void subscribeOperatorWithPublicKey(String operatorName, PublicKey operatorPublicKey) {
        operatorClientList.add(operatorName);
        operatorPublicKeysList.add(operatorPublicKey);
        operatorNameAndPublicKeyList.put(operatorName,operatorPublicKey);
    }

    /**
     * Register a client name.
     * @param clientName client name.
     */
    public void subscribeClient(String clientName) {
        clientClientList.add(clientName);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Trust operations--------------------------------------*/

    /**
     * Create a new trust. Special operation.
     * Participating HSMs and operators are given at start.
     * Random participating HSM is used.
     *
     * @param hmsIdsList a list of the HSMs public keys to add to the trust.
     * @param operatorPublicKeyIndexList a list of the operator public keys.
     * @return true if success else false.
     */
    public boolean createNewTrust(List<Integer> hmsIdsList, List<Integer> operatorPublicKeyIndexList) {
        //get random hsm from hsm id list given
        int workerHsmId = hmsIdsList.get(random.nextInt(hmsIdsList.size()));
        if (hsmIdCounter <= workerHsmId) { //validate
            return false;
        }

        //get chosen hsm
        HardwareSecurityModule hsm = getHsmById(workerHsmId);
        if (hsm == null) {
            return false;
        }

        //process to get a random set of operators on a trust if it is empty
        List<PublicKey> operatorPublicKeyList = new ArrayList<>();
        if(operatorPublicKeyIndexList.isEmpty()) {
            int numberOfOperatorPublicKeys = operatorPublicKeysList.size();
            int halfOperatorPublicKeys = (numberOfOperatorPublicKeys/2 > 0) ? numberOfOperatorPublicKeys/2 : 1;

            Collections.shuffle(operatorPublicKeysList);
            for(int i=0;i<halfOperatorPublicKeys;i++)
                operatorPublicKeyList.add(operatorPublicKeysList.get(i));
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

        Trust trust = hsm.createTrust( new ArrayList<>(hsmPublicKeyList), new ArrayList<>(operatorPublicKeyList));
        trustList.add(trust);
        return true;
    }

    /**
     * Update trust with new data.
     * @param trustID ID of trust to update.
     */
    public void updateTrust(int trustID, List<Integer> listHsmID, List<Integer> listOperatorID) {



    }

    /**
     * <p>Operator sign a trust with his domain key pair.</p>
     * <p>If operator already signed the trust the old signature is removed and a new one is created.</p>
     * @param trustId the id of the trust to sign.
     * @param privateKey public key of operator to sign trust with.
     * @return true if success else false.
     * @deprecated TODO: need to change.
     */
    public boolean operatorSignTrust(int trustId, PrivateKey privateKey) {

        //get trust by id
        Trust unsignedTrust = getTrustById(trustId, TRUST_LIST_TYPE.UNSIGNED);

        //verify if signature already exists
        //checks if signature is for the same trust and if the domain being used is the same (same person)
        List<OperatorSignature> trustSignatureList = getOperatorTrustSignatureByTrustId(trustId);
        for(OperatorSignature operatorSignature : trustSignatureList) {
            if(operatorSignature.generalSignature().publicKey().equals(privateKey))
                operatorsTrustSignatureList.remove(operatorSignature);
        }

        //get free hsm that belongs in trust (in this case its just random) using the public keys in Trust
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
        GeneralSignature generalSignature = new GeneralSignature(hsm.signatureRSA(hash, privateKey), null);
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
        if (hsm == null) {
            System.out.println("Error finding hsm.");
            return -1;
        }

        Domain newDomain = hsm.createDomain(trust, domainKeysType, ++domainIdCounter);
        if (newDomain == null)
            System.out.println("Failure creating domain, signature failed.");
        else if(domainKeysType == HardwareSecurityModule.DOMAIN_KEYS_TYPE.ASYMMETRIC_KEY_DOMAIN) {
            operatorPublicKeysList.add(newDomain.domainContent().domainKeys().masterKeyToken().publicKey());
            //operatorIdentifierList.add(getHashIdentifier(newDomain));
        }
        domainsList.add(newDomain);

        return domainIdCounter;
    }

    /**
     * Check if domain exists in the domain list.
     * @param domainId the domain ID to check for existence.
     * @return true if found else false.
     */
    public boolean checkDomainExist(int domainId) {
        return getDomainById(domainId) != null;
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
    /*--------------------------------------------Setter-------------------------------------------*/



    /*---------------------------------------------------------------------------------------------*/
    /*-------------------------------------------Getters-------------------------------------------*/

    /**
     * Get all operator names.
     * @return list of all operators names.
     */
    public List<String> getOperatorsNames() {
        return operatorClientList;
    }

    /**
     * Get operator public key by index in list, this index is interpreted as a ID.
     * @param index the index position of the public key to get.
     * @return a public key.
     */
    private PublicKey getOperatorPublicKeyById(int index) {
        return operatorPublicKeysList.get(index);
    }

    /**
     * Get an operator name from its public key.
     * @param publicKeyTarget the public key of the operator.
     * @return the name of the operators who as that public key.
     */
    private String getOperatorNameFromPublicKey(PublicKey publicKeyTarget) {
        Set<String> setOperatorName = operatorNameAndPublicKeyList.keySet();
        String targetName = "";

        for (String operatorName : setOperatorName) {
            PublicKey publicKey = operatorNameAndPublicKeyList.get(operatorName);
            if (publicKey.equals(publicKeyTarget)) {
                targetName = operatorName;
                break;
            }
        }

        return targetName;
    }

    /**
     * Get a hsm by its public key.
     * @param publicKey the public key of the hsm to get.
     * @return The hsm found or null if not.
     */
    private HardwareSecurityModule getHsmByPublicKey(PublicKey publicKey) {
        for(HardwareSecurityModule hsm : hsmList) {
            if(hsm.getPublicKey().equals(publicKey))
                return hsm;
        }
        return null;
    }

    /**
     * Get a hsm identifier by its public key.
     * @param publicKey the public key of the hsm to get.
     * @return The hsm identifier or -1 if not.
     */
    private Integer getHsmIdentifierByPublicKey(PublicKey publicKey) {
        for(HardwareSecurityModule hsm : hsmList) {
            if(hsm.getPublicKey().equals(publicKey))
                return hsm.getId();
        }
        return -1;
    }

    /**
     * Gets an hsm from a given int id.
     * @param id int id to identify hsm.
     * @return the hsm with the pretended id or null if not found.
     */
    private HardwareSecurityModule getHsmById(int id) {
        for (HardwareSecurityModule hsm : hsmList) {
            if(hsm.getId() == id)
                return hsm;
        }
        return null;
    }

    /**
     * Get a random hsm from the list.
     * @return a random existing hsm.
     */
    private HardwareSecurityModule getRandomHSM() {
        return hsmList.get(random.nextInt(hsmList.size()));
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
     * Get HashMap of Operator Name as key and associated public key.
     * @return a hashMap of Operator name (String) and public key (PublicKey).
     */
    public HashMap<String, PublicKey> getOperatorNameAndPublicKey() {
        return operatorNameAndPublicKeyList;
    }

    /**
     * Get the name of the operators in a specific trust.
     * @param trustIdentifier the trust that we want to operators from.
     * @return a list of the operators name in the trust.
     */
    public List<String> getTrustOperators(int trustIdentifier) {
        Trust trust = getTrustById(trustIdentifier, TRUST_LIST_TYPE.SIGNED);
        if (trust == null)
            return new ArrayList<>();
        TrustContent trustContent = trust.getTrustContent();

        List<PublicKey> listTrustOperatorsPublicKeys = trustContent.getOperatorPublicKeys();
        List<String> listOperatorsName = new ArrayList<>();

        for (PublicKey publicKey : listTrustOperatorsPublicKeys) {
            String operatorName = getOperatorNameFromPublicKey(publicKey);
            if (!operatorName.equals("")) {
                listOperatorsName.add(operatorName);
            }
        }
        return listOperatorsName;
    }

    /**
     * Get the ids of the hsm in a trust.
     * @param trustIdentifier the trust that we want the hsm ids from.
     * @return  a list of the hsm ids in a specified trust.
     */
    public List<String> getTrustHsm(int trustIdentifier) {
        Trust trust = getTrustById(trustIdentifier, TRUST_LIST_TYPE.SIGNED);
        if (trust == null)
            return new ArrayList<>();
        TrustContent trustContent = trust.getTrustContent();

        List<PublicKey> listTrustHsmPublicKeys = trustContent.getHsmPublicKeys();
        List<String> listHsmIDs = new ArrayList<>();
        for (PublicKey publicKey : listTrustHsmPublicKeys) {
            int hsmID = getHsmIdentifierByPublicKey(publicKey);
            if (hsmID != -1) {
                listHsmIDs.add(String.valueOf(hsmID));
            }
        }
        return listHsmIDs;
    }

    /**
     * Gets a trust from a given int id
     * @param id int id to identify trust
     * @param type the type of trust list we want to check
     *             signed or unsigned
     * @return the trust with the pretended id or null if not found
     */
    private Trust getTrustById(int id, TRUST_LIST_TYPE type) {
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
    private Domain getDomainById(int domainId) {
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

    /**
     * Get List of HSM ID as string.
     * @return a List of the HSM IDs.
     */
    public List<String> getListHsmIdentifier() {
        List<String> hsmNameList = new ArrayList<>();

        for (HardwareSecurityModule hsm : hsmList)
            hsmNameList.add(String.valueOf(hsm.getId()));

        return hsmNameList;
    }

    /**
     * List of the Ids of all the valid (signed) trusts.
     * @return list with the IDs of the Trusts
     */
    public List<Integer> getListTrustID() {
        List<Integer> listTrust = new ArrayList<>();

        for (Trust trust : trustList) {
            listTrust.add(trust.getTrustContent().getId());
        }

        return listTrust;
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Show information--------------------------------------*/

    public String showTrustsTable(int domainId, TRUST_LIST_TYPE type) {
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

        for (int i = 0; i< operatorPublicKeysList.size(); ++i) {
            PublicKey publicKey = operatorPublicKeysList.get(i);
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

    public String showHsmTable() {
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