package com.company.entities;

import com.company.mvc.controller.ClientController;
import com.company.mvc.model.ClientModel;
import com.company.mvc.view.ClientView;

public class Client {
    /*private void encryptWithDomain() {
        try {
            String fileContent = readFile("/home/victor/test.txt");

            String base64EncryptedData = server.encryptWithDomain(fileContent.getBytes(StandardCharsets.UTF_8), this.domainId);

            writeFile(base64EncryptedData,"/home/victor/test.enc");
        } catch (RemoteException e) {
            System.out.println("Error remote: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error client I/O (" + e.getLocalizedMessage() + "): " + e.getMessage());
        }
    }

    private void decryptWithDomain() {
        try {
            String base64FileContent = readFile("/home/victor/test.enc");

            byte[] data = server.decryptWithDomain(base64FileContent, this.domainId);
            String content = new String(data,StandardCharsets.UTF_8);
            writeFile(content,"/home/victor/test.dec");
        } catch (RemoteException e) {
            System.out.println("Error remote: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error unknown: " + e.getMessage());
        }
    }*/

    public static void main(String[] args) {
        try {
            ClientModel clientModel = new ClientModel();
            ClientView clientView = new ClientView();

            ClientController clientController = new ClientController(clientModel, clientView);

            clientController.start();

        } catch (Exception exception) {
            System.err.println("-> Exception: " + exception.getMessage());
        }
    }
}
