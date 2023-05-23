package com.company.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;

public interface ServerInterface extends Remote {

    void subscribeOperatorWithPublicKey(String name, PublicKey publicKey) throws RemoteException;

    void subscribeClient(String name) throws RemoteException;

    boolean checkDomainExists(int domainId) throws RemoteException;

    /*---------------------------------------------------------------------------------------------*/
    /*----------------------------------------Get from server--------------------------------------*/

    public List<String> getOperatorsNames() throws RemoteException;

    HashMap<String, PublicKey> getOperatorNameAndPublicKey() throws RemoteException;

    List<String> getListHsmIdentifier() throws RemoteException;

    public List<Integer> getListTrustID() throws RemoteException;

    public List<Integer> getListUnsignedTrustID() throws RemoteException;

    public List<String> getTrustOperators(int trustIdentifier) throws RemoteException;

    public List<String> getTrustHsm(int trustIdentifier) throws RemoteException;

    /*---------------------------------------------------------------------------------------------*/

    boolean createNewTrust(List<Integer> hsmIdList, List<Integer> operatorPublicKeyList, int quorum) throws RemoteException;

    public boolean buildTrust(int trustID,List<Integer> hsmIdsList,List<String> listOperatorName, int quorum) throws RemoteException;

    void signTrust(int trustId) throws RemoteException;

    public void operatorSignTrust(int trustID, PrivateKey privateKey) throws RemoteException;

    boolean verifyTrustSignature(int trustId) throws RemoteException;


    int createAsyDomain(int trustId) throws RemoteException;

    int createSymDomain(int trustId) throws RemoteException;

    boolean verifyDomainSignature(int domainId) throws RemoteException;


    String encryptWithDomain(byte[] data, int domainId) throws RemoteException;

    byte[] decryptWithDomain(String encryptedDataBase64, int domainId) throws RemoteException;

    public KeyPair generateKeyPair() throws RemoteException;


    void createNewHardwareSecurityModule() throws RemoteException;

    /*---------------------------------------------------------------------------------------------*/

    /*String showOperatorPublicKeys() throws RemoteException;

    String showHsmPublicKeys() throws RemoteException;

    String showDomains() throws RemoteException;

    String showDomain(int domainId) throws RemoteException;

    String showSignedTrusts(int opDomainId) throws RemoteException;

    String showUnsignedTrusts(int opDomainId) throws RemoteException;

    String showOperatorTrustSignatures(int trustIdentification) throws RemoteException;*/
}
