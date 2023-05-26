package com.company.entities;

import com.company.keystructure.Domain;
import com.company.utility.GeneralManager;
import com.company.hsm.HardwareSecurityModule;
import com.company.interfaces.ServerInterface;
import com.company.utility.CryptographyOperations;

import java.net.InetAddress;

import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.LocateRegistry;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

public class Server extends UnicastRemoteObject implements ServerInterface {

    /*----------------------------------Variables and constructor----------------------------------*/

    GeneralManager generalManager;

    private static final Scanner readInput = new Scanner(System.in);

    public Server() throws RemoteException {
        super();

        generalManager = new GeneralManager(10);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Show information--------------------------------------*/

    /*public String showSignedTrusts(int opDomainId) {
        System.out.println(">Showing signed trusts");
        return generalManager.showTrustsTable(opDomainId, GeneralManager.TRUST_LIST_TYPE.SIGNED);
    }

    public String showUnsignedTrusts(int opDomainId) {
        System.out.println(">Showing unsigned trusts");
        return generalManager.showTrustsTable(opDomainId, GeneralManager.TRUST_LIST_TYPE.UNSIGNED);
    }

    public String showOperatorTrustSignatures(int trustIdentification) {
        System.out.println(">Showing operator signatures for trust: " + trustIdentification);
        return generalManager.showOperatorTrustSignatures(trustIdentification);
    }

    public String showOperatorPublicKeys() {
        System.out.println(">Showing operator public keys");
        return generalManager.showOperatorPublicKeys();
    }

    public String showHsmPublicKeys() {
        System.out.println(">Showing hsm public keys");
        return generalManager.showHsmPublicKeys();
    }

    public String showDomains() {
        System.out.println(">Showing domains");
        return generalManager.showDomains();
    }

    public String showDomain(int domainId) {
        System.out.println(">Showing domain " + domainId);
        return generalManager.showDomain(domainId);
    }*/

    public boolean checkDomainExists(int domainId) {
        return generalManager.checkDomainExist(domainId);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------------Get---------------------------------------------*/

    public List<String> getOperatorsNames() throws RemoteException {
        return generalManager.getOperatorsNames();
    }

    public HashMap<String, PublicKey>  getOperatorNameAndPublicKey() throws RemoteException {
        System.out.println(">Getting hasMap of operator name and public key.");
        return generalManager.getOperatorNameAndPublicKey();
    }

    public List<String> getListHsmIdentifier() throws RemoteException{
        System.out.println(">Getting hardware security module IDs.");
        return generalManager.getListHsmIdentifier();
    }

    public List<Integer> getListTrustID() throws RemoteException {
        System.out.println(">Getting List of Trust ID.");
        return generalManager.getListTrustID();
    }

    public List<Integer> getListUnsignedTrustID() throws RemoteException {
        System.out.println(">Getting List of unsigned Trust ID.");
        return generalManager.getListUnsignedTrustID();
    }

    public List<String> getTrustOperators(int trustIdentifier) throws RemoteException {
        System.out.println(">Getting list of operators in a trust.");
        return generalManager.getTrustOperators(trustIdentifier);
    }

    public List<String> getTrustHsm(int trustIdentifier) throws RemoteException {
        System.out.println(">Getting list of hsm identifiers in a trust.");
        return generalManager.getTrustHsm(trustIdentifier);
    }

    public int getQuorum(int trustIdentifier) throws RemoteException {
        System.out.println("Getting quorum.");
        return generalManager.getQuorum(trustIdentifier);
    }

    public List<Integer> getListDomainID() throws RemoteException {
        return generalManager.getListDomainID();
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-------------------------------------------Operations----------------------------------------*/

    public boolean createNewTrust(List<Integer> listHsmID, List<Integer> operatorPublicKeyIndexList, int quorum) throws RemoteException{
        System.out.println(">Creating new trust");
        boolean status = generalManager.createNewTrust(listHsmID, operatorPublicKeyIndexList, quorum);
        if (status)
            System.out.println(">Success creating new trust");
        else
            System.out.println(">Failure creating new trust");
        return status;
    }

    public boolean buildTrust(int trustID,List<Integer> hsmIdsList,List<String> listOperatorName, int quorum) throws RemoteException {
        System.out.println(">Building trust");
        return generalManager.buildTrust(trustID,hsmIdsList,listOperatorName, quorum);
    }

    public boolean signTrust(int trustId) {
        System.out.println(">Hsm sign trust");
        return generalManager.signTrust(trustId);
    }

    public boolean operatorSignTrust(int trustID, PublicKey publicKey, PrivateKey privateKey) throws RemoteException {
        System.out.println(">Operator is signing a trust");
        return generalManager.operatorSignTrust(trustID, publicKey, privateKey);
    }

    public boolean verifyTrustSignature(int trustId) {
        System.out.println(">Verify domain signature");
        return generalManager.verifyTrustSignature(trustId);
    }


    public void createNewHardwareSecurityModule() {
        System.out.println(">Creating new hardware security module");
        generalManager.createNewHardwareSecurityModule();
    }


    public int createAsyDomain(int trustId) {
        System.out.println(">Creating asymmetric domain");
        return generalManager.createDomain(trustId, HardwareSecurityModule.DOMAIN_KEYS_TYPE.ASYMMETRIC_KEY_DOMAIN);
    }

    public int createSymDomain(int trustId) {
        System.out.println(">Creating symmetric domain");
        return generalManager.createDomain(trustId, HardwareSecurityModule.DOMAIN_KEYS_TYPE.SYMMETRIC_KEY_DOMAIN);
    }

    public boolean verifyDomainSignature(int domainId) {
        System.out.println(">Verify domain signature");
        return generalManager.verifyDomainSignature(domainId);
    }

    public String encryptWithDomain(byte[] data, int domainId) {
        System.out.println(">Encrypt with domain");
        return CryptographyOperations.byteToBase64String(generalManager.encryptWithDomain(data, domainId));
    }

    public byte[] decryptWithDomain(String encryptedDataBase64, int domainId) {
        System.out.println(">Decrypt with domain");
        return generalManager.decryptWithDomain(CryptographyOperations.base64ToByte(encryptedDataBase64), domainId);
    }


    public KeyPair generateKeyPair() throws RemoteException {
        System.out.println(">Generating key pair");
        return generalManager.generateKeyPairWithHSM();
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Subscribe users---------------------------------------*/

    public void subscribeOperatorWithPublicKey(String name, PublicKey publicKey) throws RemoteException {
        System.out.println(">Subscribing Operator: " + name);
        generalManager.subscribeOperatorWithPublicKey(name, publicKey);
    }

    public void subscribeClient(String name) throws RemoteException {
        System.out.println(">Subscribing Client: " + name);
        generalManager.subscribeClient(name);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------------Input-------------------------------------------*/

    private static void readInput() {
        int option = 0;
        while(option != 3) {
            System.out.println(
                    """
                            1. print operators
                            2. print clients
                            3. quit
                            """
            );
            System.out.print("Type option: ");
            option = readInput.nextInt();
            switch (option) {
                case 1 -> System.out.println("Placeholder print operators.");
                case 2 -> System.out.println("Placeholder print clients.");
            }

        }
    }

    /*---------------------------------------------------------------------------------------------*/

    public static void main(String[] args) {
        try {
            String ipServer = InetAddress.getLocalHost().getHostAddress();
            System.out.println("Server ip: " + ipServer);

            System.setProperty("java.rmi.server.hostname", ipServer);
            LocateRegistry.createRegistry(1099);
            Server server = new Server();
            Naming.rebind("server", server);

            System.out.println("*** Server Started ***");

            readInput();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}