package com.company.entities;

import com.company.interfaces.OperatorInterface;
import com.company.interfaces.ServerInterface;

import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Operator extends UnicastRemoteObject implements OperatorInterface {

    private static final Scanner readInput = new Scanner(System.in);

    private final ServerInterface server;

    /**
     * Operator name string identifier, best if unique
     */
    private final String operatorName;

    /**
     * Identifier of domain belonging to this operator
     */
    private final int domainId;

    public Operator(String operatorName, ServerInterface server) throws RemoteException {
        super();
        this.operatorName = operatorName;
        this.domainId = server.createAsyDomain(1);
        this.server = server;

        System.out.println("Domain created for operator, domain id number: " + domainId);
        System.out.println(server.showDomain(domainId));
        System.out.println("Operator name: " + operatorName);
    }

    private String getOperatorName() {
        return operatorName;
    }

    /*private void showSignedTrusts() throws Exception{
        System.out.println(">Showing signed trusts.");
        String text = server.showSignedTrusts(this.domainId);
        System.out.println(text);
    }

    private void showUnsignedTrusts() throws Exception {
        System.out.println(">Showing unsigned trusts.");
        String text = server.showUnsignedTrusts(this.domainId);
        System.out.println(text);
    }

    private void showOperatorTrustSignatures() throws Exception {
        System.out.print(">Showing operator trust signatures.\n#Trust id: ");
        int trustIdentification = readInput.nextInt();
        String text = server.showOperatorTrustSignatures(trustIdentification);
        System.out.println(text);
    }

    private void showOperatorPublicKeys() throws Exception {
        System.out.println(">Showing operator public keys.");
        String text = server.showOperatorPublicKeys();
        System.out.println(text);
    }

    private void showHsmPublicKeys() throws Exception {
        System.out.println(">Showing hsm public keys.");
        String text = server.showHsmPublicKeys();
        System.out.println(text);
    }

    private void showHardwareSecurityModules() throws Exception {
        System.out.println(">Showing hsm.");
        String text = server.showHardwareSecurityModules();
        System.out.println(text);
    }

    private void showDomains() throws Exception {
        System.out.println(">Showing domains.");
        String text = server.showDomains();
        System.out.println(text);
    }

    private void showOwnDomain() throws Exception {
        System.out.println(">Showing own domain.");
        String text = server.showDomain(domainId);
        System.out.println(text);
    }

    private void createNewTrust() throws Exception {
        List<Integer> hsmIdList = new ArrayList<>();
        List<Integer> operatorIndexList = new ArrayList<>();

        showHardwareSecurityModules();

        int hsmIdChoice;
        while (true) {
            System.out.print("#Type hsm id to add to trust (-1 to leave): ");
            hsmIdChoice = readInput.nextInt();
            if(hsmIdChoice == -1)
                break;
            if(!hsmIdList.contains(hsmIdChoice))
                hsmIdList.add(hsmIdChoice);
        }

        showOperatorPublicKeys();
        int operatorIndexChoice;
        while (true) {
            System.out.print("#Type operator index to add to trust (-1 to leave): ");
            operatorIndexChoice = readInput.nextInt();
            if(operatorIndexChoice == -1)
                break;
            if(!operatorIndexList.contains(operatorIndexChoice))
                operatorIndexList.add(operatorIndexChoice);
        }

        server.createNewTrust(hsmIdList, operatorIndexList);
        System.out.println(">Done.");
    }

    private void signTrust() throws Exception {
        showUnsignedTrusts();

        System.out.print("#Type trust id to sign: ");
        int trustId = readInput.nextInt();

        server.signTrust(trustId);

        System.out.println(">Done.");
    }

    private void verifyDomainSignature() throws Exception {
        showDomains();

        System.out.print("#Type domain id to verify: ");
        int domainId = readInput.nextInt();
        boolean status = server.verifyDomainSignature(domainId);
        if(status)
            System.out.println(">Domain is valid.");
        else
            System.out.println(">Domain is not valid.");
    }

    private void verifyTrustSignature() throws Exception {
        showSignedTrusts();

        System.out.print("#Type trust id to verify: ");
        int domainId = readInput.nextInt();
        boolean status = server.verifyTrustSignature(domainId);
        if(status)
            System.out.println(">Trust is valid.");
        else
            System.out.println(">Trust is not valid.");
    }

    private void createNewHardwareSecurityModule() throws Exception {
        System.out.println(">Creating new hsm.");
        server.createNewHardwareSecurityModule();
    }

    private void createSymmetricDomain() throws Exception{
        showSignedTrusts();

        System.out.print("Type id of trust to use: ");
        int trustId = readInput.nextInt();
        int createdDomainId = server.createSymDomain(trustId);
        System.out.println(">Done, domain id: " + createdDomainId);
    }

    private void createAsymmetricDomain() throws Exception{
        showSignedTrusts();

        System.out.print("Type id of trust to use: ");
        int trustId = readInput.nextInt();
        int createdDomainId = server.createAsyDomain(trustId);
        System.out.println(">Done, domain id: " + createdDomainId);
    }

    private void showMenu() throws Exception {
        int decision = 0;

        while (decision != 9) {
            System.out.println(
                            """
                            Show menu
                            1. Show trusts
                            2. Show unsigned trusts
                            3. Show operator trust signatures
                            4. Show operator public keys
                            5. Show hsm public keys
                            6. Show hsm
                            7. Show own domain
                            8. Show Domains
                            9. Go back
                            """
            );
            System.out.print("#Option: ");
            decision = readInput.nextInt();
            switch (decision) {
                case 1 -> showSignedTrusts();
                case 2 -> showUnsignedTrusts();
                case 3 -> showOperatorTrustSignatures();
                case 4 -> showOperatorPublicKeys();
                case 5 -> showHsmPublicKeys();
                case 6 -> showHardwareSecurityModules();
                case 7 -> showOwnDomain();
                case 8 -> showDomains();
            }
        }
    }

    private void trustMenu() throws Exception {
        int decision = 0;

        while (decision != 9) {
            System.out.println(
                    """
                    Trust menu
                    1. Show trusts                      5. Sign trust with operator
                    2. Show unsigned trusts             6. Sign trust with hsm
                    3. Show operator trust signatures   7. Verify trust
                    4. Create new unsigned trust        8. Show participating trust
                    9. Go back
                    """
            );
            System.out.print("#Option: ");
            decision = readInput.nextInt();
            switch (decision) {
                case 1 -> showSignedTrusts();
                case 2 -> showUnsignedTrusts();
                case 3 -> showOperatorTrustSignatures();
                case 4 -> createNewTrust();
                case 5 -> operatorSignTrust();
                case 6 -> signTrust();
                case 7 -> verifyTrustSignature();
                case 8 -> System.out.println("Placeholder");
            }
        }
    }

    private void domainMenu() throws Exception {
        int decision = 0;

        while (decision != 9) {
            System.out.println(
                    """
                    Domain menu
                    1. Show domains
                    2. Show own domain

                    3. Create asymmetric domain
                    4. Create symmetric domain

                    5. verify domain

                    9. Go back
                    """
            );
            System.out.print("#Option: ");
            decision = readInput.nextInt();
            switch (decision) {
                case 1 -> showDomains();
                case 2 -> showOwnDomain();
                case 3 -> createAsymmetricDomain();
                case 4 -> createSymmetricDomain();
                case 5 -> verifyDomainSignature();
            }
        }
    }

    private void hsmMenu() throws Exception{
        int decision = 0;

        while (decision != 9) {
            System.out.println(
                    """
                    Hsm menu
                    1. Show hsm
                    2. Show hsm public key

                    3. Create new hsm

                    9. Go back
                    """
            );
            System.out.print("#Option: ");
            decision = readInput.nextInt();
            switch (decision) {
                case 1 -> showHardwareSecurityModules();
                case 2 -> showHsmPublicKeys();
                case 3 -> createNewHardwareSecurityModule();

            }
        }
    }

    private void menu() throws Exception {
        int decision = 0;

        while(decision != 20) {
            System.out.print(
                            """
                            Menu:
                            1. Show menu
                            2. Trust menu
                            3. Domain menu
                            4. Hsm menu

                            20. Go back
                            """
            );

            System.out.print("#Option: ");
            decision = readInput.nextInt();
            switch (decision) {
                case 1 -> showMenu();
                case 2 -> trustMenu();
                case 3 -> domainMenu();
                case 4 -> hsmMenu();
            }
        }
    }*/

    public static void main(String[] args) {

        try {
            // Get own host ip
            String clientIp = InetAddress.getLocalHost().getHostAddress();
            System.out.println("Operator ip is: " + clientIp);

            // Get Operator name
            String operatorName;
            do {
                System.out.print("Type operator name: ");
                operatorName = readInput.nextLine();
            } while (operatorName.equals(""));

            // Setup connection and connect to server
            Registry registry;
            ServerInterface server = null;
            boolean flag = false;
            do {
                try {
                    // Get Server IP
                    System.out.print("Type Server ip (ENTER uses LocalHost): ");
                    String ipServer = readInput.nextLine();
                    if(ipServer.equals(""))
                        ipServer = clientIp;

                    System.setProperty("java.rmi.server.hostname", clientIp);
                    registry = LocateRegistry.getRegistry(ipServer, 1099);
                    server = (ServerInterface) registry.lookup("server");
                    flag = true;
                } catch (Exception e) {
                    System.out.println("-> Exception: Error connecting to server:" + e.getMessage());
                }
            } while (!flag);
            System.out.println("*** Connected to server ***");

            // Subscribe Operator
            Operator operator = new Operator(operatorName, server);
            server.subscribeOperator(operator.getOperatorName());

            //TODO: RUN

            System.out.println("Exiting...");

        }catch (Exception e) {
            System.err.println("-> Exception: " + e.getMessage());
            System.out.println("Exiting...");
        }
    }
}
