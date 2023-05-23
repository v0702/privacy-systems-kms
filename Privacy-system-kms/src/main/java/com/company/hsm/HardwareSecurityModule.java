package com.company.hsm;

import com.company.keystructure.*;
import com.company.utility.CryptographyOperations;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * And hardware security module that can perform cryptographic operations
 * an also create and verify trusts, and create and unwrap domains.
 * </p>
 * <p>
 * Functionalities:
 *     <ul>
 *     <li>one</li>
 *     <li>one</li>
 *     <li>one</li>
 *     <li>one</li>
 * </ul>
 * </p>
 * <pre>
 *
 * </pre>
 * @author victor
*/
public class HardwareSecurityModule extends CryptographyOperations {

    /*----------------------------------Variables and constructor----------------------------------*/

    /**
     * Types of domains master key that we can have:<p>
     * SYMMETRIC_KEY for AES crypto operations.<p>
     * ASYMMETRIC_KEY for RSA crypto operations.
     */
    public enum DOMAIN_KEYS_TYPE{
        ASYMMETRIC_KEY_DOMAIN,
        SYMMETRIC_KEY_DOMAIN
    }

    /**
     * This hardware security module public and private key.
     */
    private final KeyPair pair;

    /**
     * This hardware security module iterative id, unique.
     */
    private final int id;

    /**
     * This hardware security module word id, unique.
     */
    private final String wordlyIdentifier;

    /**
     * Constructor for the Hardware Security Module.
     */
    public HardwareSecurityModule(int id, int keySize, String algorithm){
        this.id = id;
        this.pair = generateKeyPair(keySize,algorithm);
        this.wordlyIdentifier = getHashIdentifier(this.hashCode());
        if (this.pair == null)
            throw new IllegalArgumentException("Pair is null, wrong algorithm given");
    }

    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------Unwrap domain keys-------------------------------------*/

    /**
     * <p>
     * Get the SecretPrivate key in domain, by finding the token encrypted with this hsm
     * public key and decrypting with its own private key, getting the symmetric key to use
     * for decrypting the master key.<p> The Domain must be signed and valid, and the trust
     * in the domain must also be valid and include the hsm to perform this operation.
     * </p>
     * @param domain the domain to unwrap
     * @return secret key of SecretKey type or null if operation failure
     */
    private SecretKey unwrapSymmetricDomain(Domain domain) {

        // getting the token made by for this specific hsm
        // and getting the masterKeyToken
        Token wrapKeyToken = domain.domainContent().domainKeys().getWrapKeyToken(this.getPublicKey());
        Token masterKeyToken = domain.domainContent().domainKeys().masterKeyToken();
        if (wrapKeyToken == null || masterKeyToken == null)// validate tokens
            return null;

        byte[] wrapKeyByte = decryptRSA(wrapKeyToken.encryptedKey(), this.getPrivateKey());
        if(wrapKeyByte == null)// validate the RSA decryption result
            return null;

        SecretKey wrapKey = byteToSecretKey(wrapKeyByte, CryptographyOperations.KEY_GENERATOR_ALGORITHM_AES);
        byte[] masterKeyByte = decryptAES(masterKeyToken.encryptedKey(), wrapKey);
        if(masterKeyByte == null)// validate the AES decryption result
            return null;

        return byteToSecretKey(masterKeyByte, CryptographyOperations.KEY_GENERATOR_ALGORITHM_AES);
    }

    /**
     * <p>
     * Get the KeyPair key pair in domain, by finding the token encrypted with this hsm
     * public key and decrypting with its own private key, getting the asymmetric key to use
     * for decrypting the master key.<p> The Domain must be signed and valid, and the trust
     * in the domain must also be valid and include the hsm to perform this operation.<p>
     * The key pair is stored as a token, where the encrypted private key is stored as byte array and
     * the public key is stored non-encrypted in the token as well.
     * </p>
     * @param domain the domain to unwrap
     * @return key pair of KeyPair type or null if operation failure
     */
    private KeyPair unwrapAsymmetricDomain(Domain domain) {

        // getting the token made by for this specific hsm
        // and getting the masterKeyToken
        Token wrapKeyToken = domain.domainContent().domainKeys().getWrapKeyToken(this.getPublicKey());
        Token masterKeyToken = domain.domainContent().domainKeys().masterKeyToken();
        if(wrapKeyToken == null)// validate token
            return null;

        byte[] wrapKeyByte = decryptRSA(wrapKeyToken.encryptedKey(), this.getPrivateKey());
        if(wrapKeyByte == null)// validate the RSA decryption result
            return null;


        SecretKey wrapSecretKey = byteToSecretKey(wrapKeyByte, CryptographyOperations.KEY_GENERATOR_ALGORITHM_AES);
        byte[] masterKeyByte = decryptAES(masterKeyToken.encryptedKey(), wrapSecretKey);
        if(masterKeyByte == null)// validate the AES decryption result
            return null;

        PrivateKey privateKey = byteToPrivateKey(masterKeyByte, CryptographyOperations.KEY_GENERATOR_ALGORITHM_RSA);
        if(privateKey == null)// validate the private key transformation
            return null;

        return new KeyPair(masterKeyToken.publicKey(), privateKey);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*------------------------------------Encryption with domain-----------------------------------*/

    public byte[] encryptWithDomain(byte[] data, Domain domain) {
        Trust trust = domain.domainContent().trust();
        // verify that domain signature is valid, trust signature is valid, and hsm public key is in trust
        if(!verifyDomainSignature(domain) && !verifyTrustSignature(trust) && !trust.getTrustContent().checkExistHardwarePublicKey(this.getPublicKey()))
            return null;

        SecretKey key = unwrapSymmetricDomain(domain);

        return encryptAES(data, key);
    }

    public byte[] decryptWithDomain(byte[] encryptedData, Domain domain) {
        Trust trust = domain.domainContent().trust();
        // verify that domain signature is valid, trust signature is valid, and hsm public key is in trust
        if(!verifyDomainSignature(domain) && !verifyTrustSignature(trust) && !trust.getTrustContent().checkExistHardwarePublicKey(this.getPublicKey()))
            return null;

        return decryptAES(encryptedData, unwrapSymmetricDomain(domain));
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-------------------------------------Signature operations------------------------------------*/

    /**
     * <p>
     * Sign a trust content.
     *</p>
     * <p>
     * For this to be possible, the operators must also sign the trustContent, the
     * hsm will verify these and also check if the hsm public key
     * is in the trustContent so that it can sign it.
     * </p>
     * @param trust the trustContent to sign
     * @param operatorsSignaturesList a list of TrustSignatures, these signatures have
     *                                the operators signatures of the trustContent
     * @return true if successful or false if not
     */
    public boolean signTrust(Trust trust, List<OperatorSignature> operatorsSignaturesList) {
        byte[] hash = hashSum(objectToByte(trust.getTrustContent()), HASH_ALGORITHM_1);

        boolean publicKeysMatch = true;
        boolean allSignaturesValid = true;

        if(operatorsSignaturesList == null)
            return false;
        if(operatorsSignaturesList.size() == 0)
            return false;

        // check if hsm public is in trustContent
        if(!trust.getTrustContent().checkExistHardwarePublicKey(getPublicKey()))
            publicKeysMatch = false;

        // All cases are verified, even if a failed case is found early to prevent timing attack
        // So it is time constant
        // check if operator public key is in trustContent
        for (OperatorSignature operatorSignature : operatorsSignaturesList) {
            GeneralSignature signature = operatorSignature.generalSignature();
            if (!trust.getTrustContent().checkExistOperatorPublicKey(signature.publicKey())) {
                // leave if there is a signature whose public key is not in trustContent
                publicKeysMatch = false;
            }
            else if(!checkSignature(hash, signature.signature(), signature.publicKey())) {
                    // leave if there is a signature that is not valid
                    allSignaturesValid = false;
                }
        }

        // if signatures are valid and public keys are valid then we can sign trustContent
        // and set store signature in trust
        if (publicKeysMatch && allSignaturesValid) {
            trust.setSignature(new GeneralSignature(signData(hash), getPublicKey()));
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Sign data with a domain, verify the validity of the domain signature
     * @param data the hash of data to sign in byte array format
     * @param domain the domain to unwrap and use key to sign domain
     * @return the signature of the data as a GeneralSignature type or null if
     * any signature fails
     */
    public GeneralSignature signWithDomain(byte[] data, Domain domain) {
        if(!verifyDomainSignature(domain)) {
            System.out.println("Domain signature not valid.");
            return null;
        }

        if(!verifyTrustSignature(domain.domainContent().trust())) {
            System.out.println("Domain trust signature not valid.");
            return null;
        }

        KeyPair keyPair = unwrapAsymmetricDomain(domain);
        if(keyPair != null) {
            byte[] signatureByte = signData(data, keyPair.getPrivate());
            return new GeneralSignature(signatureByte, keyPair.getPublic());
        }
        else {
            System.out.println("Key pair not valid.");
            return null;
        }
    }

    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------Trust operations---------------------------------------*/

    /**
     * Create a new trust. Special operation.
     * @param hsmPublicKeysList the list of hsm public keys to add to trust.
     * @param operatorPublicKeysList the list of operator public keys to add to trust.
     * @return a signed trust.
     */
    public Trust createTrust(List<PublicKey> hsmPublicKeysList, List<PublicKey> operatorPublicKeysList, int quorum) {
        TrustContent trustContent = new TrustContent(hsmPublicKeysList,operatorPublicKeysList, quorum, new byte[0], -1);
        byte[] hash = hashSum(CryptographyOperations.objectToByte(trustContent), CryptographyOperations.HASH_ALGORITHM_1);
        GeneralSignature signature = new GeneralSignature(this.signData(hash), this.getPublicKey());

        return new Trust(trustContent, signature);
    }

    public Trust buildTrust(Trust trust,List<PublicKey> hsmPublicKeysList, List<PublicKey> operatorPublicKeysList, int quorum) {
        TrustContent oldTrustContent = trust.getTrustContent();
        List<PublicKey> newHsmPublicKeysList = new ArrayList<>(oldTrustContent.getHsmPublicKeys());
        List<PublicKey> newOperatorPublicKeysList = new ArrayList<>(oldTrustContent.getOperatorPublicKeys());
        newHsmPublicKeysList.addAll(hsmPublicKeysList);
        newOperatorPublicKeysList.addAll(operatorPublicKeysList);

        byte[] predecessorHash = this.hashSum(objectToByte(trust),CryptographyOperations.HASH_ALGORITHM_1);

        TrustContent trustContent = new TrustContent(newHsmPublicKeysList,newOperatorPublicKeysList, quorum,predecessorHash,oldTrustContent.getId());

        return new Trust(trustContent,null);
    }

    /**
     * Check if a trust is valid or not by verifying the signature.
     * @param trust the trust to validate.
     * @return true if signature is valid or false.
     */
    public boolean verifyTrustSignature(Trust trust) {
        if(trust.getSignature() == null)// verify signature exists
            return false;

        //TODO: Need to validate the public key in the signature, how do I trust it?
        PublicKey hsmPublicKey = trust.getSignature().publicKey();
        if (!trust.getTrustContent().checkExistHardwarePublicKey(hsmPublicKey))// check if public key used for signature is in trust
            return false;

        byte[] trustDataHash = this.hashSum(objectToByte(trust.getTrustContent()), HASH_ALGORITHM_1);
        if(trustDataHash == null)// check if hash is correct
            return false;

        return this.checkSignature(trustDataHash, trust.getSignature().signature(), hsmPublicKey);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*----------------------------------------Domain Operations------------------------------------*/

    /**
     * Create a DomainKeys structure, generates 2 sets of Secret Keys
     * one to wrap the other, it then wraps the wrapper key with the
     * hsm public keys in the given trust
     * @param trust the trust to be used for creating the DomainKeys
     * @return the domainKeys or null if the trust verification fails
     *
     */
    private DomainKeys createDomainKeys(Trust trust, DOMAIN_KEYS_TYPE domainType) {
        List<PublicKey> hsmPublicKeysList = trust.getTrustContent().getHsmPublicKeys();
        List<Token> wrapKeyTokenList = new ArrayList<>();

        // check if trust signature is correct
        if (!(trust.getTrustContent().checkExistHardwarePublicKey(getPublicKey()) && verifyTrustSignature(trust))) {
            return null;
        }

        //generate mk
        KeyPair keyPair = null;
        SecretKey masterKey = null;
        if (domainType == DOMAIN_KEYS_TYPE.ASYMMETRIC_KEY_DOMAIN)
            keyPair = generateKeyPair(RSA_KEY_LENGTH_2,KEY_GENERATOR_ALGORITHM_RSA);
        else
            masterKey = generateKey(AES_KEY_LENGTH_3, KEY_GENERATOR_ALGORITHM_AES);

        SecretKey wrapKey = generateKey(AES_KEY_LENGTH_3, KEY_GENERATOR_ALGORITHM_AES);

        //encrypt master key with k
        Token masterKeyToken;
        if (domainType == DOMAIN_KEYS_TYPE.ASYMMETRIC_KEY_DOMAIN)
            masterKeyToken = new Token(encryptAES(privateKeyToByte(keyPair.getPrivate()), wrapKey), keyPair.getPublic());
        else
            masterKeyToken = new Token(encryptAES(secretKeyToByte(masterKey), wrapKey), null);

        //encrypt k with Pk1 to Pki
        for(PublicKey hsmPublicKey : hsmPublicKeysList) {
            Token wrapKeyToken = new Token(encryptRSA(secretKeyToByte(wrapKey), hsmPublicKey), hsmPublicKey);
            wrapKeyTokenList.add(wrapKeyToken);
        }

        return new DomainKeys(masterKeyToken, wrapKeyTokenList);
    }

    /**
     * Create domain using a valid trust
     * @param trust a valid trust to be used to verify the domainKeys
     * @return signed domain or null if trust is not valid
     */
    public Domain createDomain(Trust trust, DOMAIN_KEYS_TYPE domainType, int domainId) {
        if(trust == null)
            return null;

        if(!verifyTrustSignature(trust))
            return null;

        DomainKeys domainKeys = createDomainKeys(trust, domainType);
        DomainContent domainContent =  new DomainContent(trust, domainKeys);

        // signature of the domain content
        byte[] domainContentHash = hashSum(objectToByte(domainContent), HASH_ALGORITHM_1);
        GeneralSignature signature = new GeneralSignature(signData(domainContentHash), getPublicKey());

        return new Domain(domainContent, signature, domainId);
    }

    /**
     * Check signature of a domain, returns false if signature is not valid
     * or given public key in signature is not in trust
     * @param domain the domain to validate
     * @return true if signature is valid or false if not
     */
    public boolean verifyDomainSignature(Domain domain) {
        GeneralSignature domainSignature = domain.signature();
        byte[] domainContentHash = hashSum(objectToByte(domain.domainContent()), HASH_ALGORITHM_1);

        // check if signature of domain is done by hsm in trust
        if (!domain.domainContent().trust().getTrustContent().checkExistHardwarePublicKey(domainSignature.publicKey()))
            return false;

        return checkSignature(domainContentHash, domainSignature);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-------------------General HSM Operations, sign data and verify signatures-------------------*/

    /**
     * Sign data with given private key
     * @param data the data to sign, in this case the hash of the data is signed
     * @param privateKey the private key to use for signing
     * @return byte array of the signature
     */
    private byte[] signData(byte[] data, PrivateKey privateKey) {
        return signatureRSA(data, privateKey);
    }

    /**
     * Sign data with hsm private key
     * In here the signed information is the hash of the data
     * Private key of the hsm is used to sign the data
     * @param data byte array, the data to sign
     * @return byte array of the signature
     */
    private byte[] signData(byte[] data) {
        return signatureRSA(data, this.getPrivateKey());
    }

    /**
     * Check if the signature to a given data is valid
     * @param data byte array of the data to verify signature
     * @param signature the signature that we want to check
     * @param publicKey public key to use for checking signature
     * @return true if signature is valid or false
     */
    private boolean checkSignature(byte[] data, byte[] signature, PublicKey publicKey) {
        return checkSignatureRSA(data, signature, publicKey);
    }

    /**
     * Check if the signature to a given data is valid
     * @param data byte array of the data to verify signature
     * @param generalSignature the GeneralSignature object that we want to check
     * @return true or false if signature is valid
     */
    private boolean checkSignature(byte[] data, GeneralSignature generalSignature) {
        return checkSignatureRSA(data, generalSignature.signature(), generalSignature.publicKey());
    }

    public KeyPair generateKeyPair() {
        return generateKeyPair(RSA_KEY_LENGTH_4,KEY_GENERATOR_ALGORITHM_RSA);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*------------------------Getters for object - get private or public key-----------------------*/

    private PrivateKey getPrivateKey() {
        return pair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return pair.getPublic();
    }

    public int getId() {
        return id;
    }

    public String getWordlyIdentifier() {
        return wordlyIdentifier;
    }

    /*---------------------------------------------------------------------------------------------*/
}