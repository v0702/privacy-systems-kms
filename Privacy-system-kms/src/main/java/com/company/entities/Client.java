package com.company.entities;

import com.company.mvc.controller.ClientController;
import com.company.mvc.model.ClientModel;
import com.company.mvc.view.ClientView;

public class Client {
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
