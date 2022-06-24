package com.company.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface ServerInterface extends Remote {

    void subscribeOperator(String name) throws RemoteException;

    void subscribeClient(String name) throws RemoteException;

    boolean checkDomainExists(int domainId) throws RemoteException;

    String showSignedTrusts(int opDomainId) throws RemoteException;

    String showUnsignedTrusts(int opDomainId) throws RemoteException;

    String showOperatorTrustSignatures(int trustIdentification) throws RemoteException;

    String showHardwareSecurityModules() throws RemoteException;

    String showOperatorPublicKeys() throws RemoteException;

    String showHsmPublicKeys() throws RemoteException;

    String showDomains() throws RemoteException;

    String showDomain(int domainId) throws RemoteException;


    void createNewTrust(List<Integer> hsmIdList, List<Integer> operatorPublicKeyList) throws RemoteException;

    boolean operatorSignTrust(int trustId, int domainId) throws RemoteException;

    void signTrust(int trustId) throws RemoteException;

    boolean verifyTrustSignature(int trustId) throws RemoteException;


    int createAsyDomain(int trustId) throws RemoteException;

    int createSymDomain(int trustId) throws RemoteException;

    boolean verifyDomainSignature(int domainId) throws RemoteException;


    String encryptWithDomain(byte[] data, int domainId) throws RemoteException;

    byte[] decryptWithDomain(String encryptedDataBase64, int domainId) throws RemoteException;


    void createNewHardwareSecurityModule() throws RemoteException;

}
