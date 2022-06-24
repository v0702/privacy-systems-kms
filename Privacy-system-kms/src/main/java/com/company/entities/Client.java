package com.company.entities;

import com.company.interfaces.ClientInterface;
import com.company.interfaces.ServerInterface;

import java.io.File;
import java.io.FileWriter;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Scanner;

public class Client extends UnicastRemoteObject implements ClientInterface {

    private static final Scanner readInput = new Scanner(System.in);

    private final ServerInterface server;

    private final String clientName;

    private final int domainId;

    public Client(String clientName, int domainId, ServerInterface server) throws RemoteException {
        super();
        this.clientName = clientName;
        this.server = server;
        this.domainId = domainId;

        System.out.println(server.showDomain(domainId));
        System.out.println("Client name: " + clientName);
    }

    public String getClientName() {
        return clientName;
    }

    private String readFile() throws Exception {
        System.out.print("Type file path: ");
        String filePath = readInput.next();

        File file = new File(filePath);
        Scanner fileReader = new Scanner(file);

        StringBuilder fileContent = new StringBuilder();
        while (fileReader.hasNextLine())
            fileContent.append(fileReader.nextLine()).append("\n");

        return fileContent.toString();
    }

    private void writeFile(String content) throws Exception {
        System.out.print("Type file name: ");
        String fileName = readInput.next();

        FileWriter fileWriter = new FileWriter(fileName);
        fileWriter.write(content);
        fileWriter.close();
    }

    private void encryptWithDomain() {
        try {
            String fileContent = readFile();

            String encryptedData = server.encryptWithDomain(fileContent.getBytes(), this.domainId);

            writeFile(encryptedData);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private void decryptWithDomain() {
        try {
            String base64FileContent = readFile();

            byte[] data = server.decryptWithDomain(base64FileContent, this.domainId);
            String content = new String(data);

            writeFile(content);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private void menu() {
        int decision = 0;

        while(decision != 20) {
            System.out.print(
                            """
                            Menu:
                            1. encrypt file with domain
                            2. decrypt file with domain
                            
                            20. Go back
                            """
            );

            System.out.print("#Option: ");
            decision = readInput.nextInt();
            switch (decision) {
                case 1 -> encryptWithDomain();
                case 2 -> decryptWithDomain();
            }
        }
    }

    public static void main(String[] args) {
        try {
            String clientIp = InetAddress.getLocalHost().getHostAddress();
            System.out.println("Client ip is: " + clientIp);

            System.out.print("Type Server ip: ");
            String ipServer = readInput.nextLine();
            if(ipServer.equals(""))
                ipServer = clientIp;

            System.out.print("Type Client name: ");
            String clientName = readInput.nextLine();

            System.setProperty("java.rmi.server.hostname", clientIp);
            Registry registry = LocateRegistry.getRegistry(ipServer, 1099);
            ServerInterface server = (ServerInterface) registry.lookup("server");
            System.out.println("*** Connected to server ***");


            int domainId;
            do {
                System.out.println("Type domain id for client: ");
                domainId = readInput.nextInt();
            }while(!server.checkDomainExists(domainId));

            Client client = new Client(clientName, domainId, server);
            server.subscribeClient(client.getClientName());

            client.menu();
            System.out.println("Exiting...");
        }catch (Exception e) {
            System.out.println(e.getMessage());
            System.out.println("Exiting...");
        }
    }
}
