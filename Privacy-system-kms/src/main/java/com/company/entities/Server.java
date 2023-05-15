package com.company.entities;

import com.company.utility.GeneralManager;
import com.company.hsm.HardwareSecurityModule;
import com.company.interfaces.ServerInterface;
import com.company.utility.CryptographyOperations;

import java.net.InetAddress;

import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.registry.LocateRegistry;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Server extends UnicastRemoteObject implements ServerInterface {

    /*----------------------------------Variables and constructor----------------------------------*/

    GeneralManager generalManager;

    private static final Scanner readInput = new Scanner(System.in);

    private static List<String> operatorClientList;
    private static List<String> clientClientList;

    public Server() throws RemoteException {
        super();
        operatorClientList = new ArrayList<>();
        clientClientList = new ArrayList<>();
        generalManager = new GeneralManager();
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Show information--------------------------------------*/

    public String showSignedTrusts(int opDomainId) {
        System.out.println(">Showing signed trusts");
        return generalManager.showTrusts(opDomainId, GeneralManager.TRUST_LIST_TYPE.SIGNED);
    }

    public String showUnsignedTrusts(int opDomainId) {
        System.out.println(">Showing unsigned trusts");
        return generalManager.showTrusts(opDomainId, GeneralManager.TRUST_LIST_TYPE.UNSIGNED);
    }

    public String showOperatorTrustSignatures(int trustIdentification) {
        System.out.println(">Showing operator signatures for trust: " + trustIdentification);
        return generalManager.showOperatorTrustSignatures(trustIdentification);
    }

    public String showHardwareSecurityModules() {
        System.out.println(">Showing hardware security module");
        return generalManager.showHsm();
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
    }

    public boolean checkDomainExists(int domainId) {
        return generalManager.checkDomainExist(domainId);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-------------------------------------------Operations----------------------------------------*/

    public void createNewTrust(List<Integer> hsmIdList, List<Integer> operatorPublicKeyIndexList) {
        System.out.println(">Creating new trust");
        generalManager.createUnsignedTrust(hsmIdList, operatorPublicKeyIndexList);
    }

    public boolean operatorSignTrust(int trustId, int domainId) {
        System.out.println(">Operator sign trust");
        return generalManager.operatorSignTrust(trustId, domainId);
    }

    public void signTrust(int trustId) {
        System.out.println(">Hsm sign trust");
        generalManager.signTrust(trustId);
    }

    public boolean verifyTrustSignature(int trustId) {
        System.out.println(">Verify domain signature");
        return generalManager.verifyTrustSignature(trustId);
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


    public void createNewHardwareSecurityModule() {
        System.out.println(">Creating new hardware security module");
        generalManager.createNewHardwareSecurityModule();
    }


    public String encryptWithDomain(byte[] data, int domainId) {
        System.out.println(">Encrypt with domain");
        return CryptographyOperations.byteToBase64String(generalManager.encryptWithDomain(data, domainId));
    }

    public byte[] decryptWithDomain(String encryptedDataBase64, int domainId) {
        System.out.println(">Decrypt with domain");
        return generalManager.decryptWithDomain(CryptographyOperations.base64ToByte(encryptedDataBase64), domainId);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------General functions-------------------------------------*/

    public void subscribeOperator(String name) throws RemoteException {
        System.out.println(">Subscribing Operator: " + name);
        operatorClientList.add(name);
    }

    public void subscribeClient(String name) throws RemoteException {
        System.out.println(">Subscribing Client: " + name);
        clientClientList.add(name);
    }

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
                case 1 -> System.out.println(operatorClientList.get(0).hashCode());
                case 2 -> System.out.println(clientClientList.get(0).hashCode());
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