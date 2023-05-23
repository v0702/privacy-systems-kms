package com.company.mvc.controller;

import com.company.interfaces.ServerInterface;
import com.company.mvc.model.ClientModel;
import com.company.mvc.view.ClientView;

import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.DirectoryDialogBuilder;
import org.w3c.dom.Text;

import java.io.File;
import java.io.FileWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;

import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;

import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

// TODO: remove client server subscription on closer
// TODO: logging
public class ClientController {

    Logger logger;

    private final ClientModel clientModel;
    private final ClientView clientView;

    private ServerInterface server;

    public ClientController(ClientModel clientModel, ClientView clientView) throws UnknownHostException {
        logger = Logger.getLogger("ClientControllerLogger");

        this.clientModel = clientModel;
        this.clientView = clientView;

        this.clientModel.setClientAddress(InetAddress.getLocalHost().getHostAddress());
        this.clientModel.setServerAddress(InetAddress.getLocalHost().getHostAddress());
    }

    public void start() {
        clientView.showWindow(this.clientSetupPanel());
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-----------------------------------------             ---------------------------------------*/

    private void connectToServerAndSubscribe() throws RemoteException, NotBoundException {
        System.setProperty("java.rmi.server.hostname", clientModel.getServerAddress());
        System.setProperty("sun.rmi.transport.connectionTimeout", "15000"); // Timeout for connection unused
        System.setProperty("sun.rmi.transport.tcp.handshakeTimeout", "1000"); // Timeout for setting up connection
        System.setProperty("sun.rmi.transport.tcp.responseTimeout", "1000"); //Timeout for waiting for response
        Registry registry = LocateRegistry.getRegistry(clientModel.getServerAddress(), 1099);
        server = (ServerInterface) registry.lookup("server");

        server.subscribeClient(clientModel.getClientName());
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Server functions--------------------------------------*/

    private void encryptWithDomain(File file, String encryptedFileLocation) {
        try {

            String fileContent = readFile(file);

            String base64EncryptedData = server.encryptWithDomain(fileContent.getBytes(StandardCharsets.UTF_8), this.clientModel.getDomainIdentifier());

            writeFile(base64EncryptedData,encryptedFileLocation);
        } catch (RemoteException e) {
            System.out.println("Error remote: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error client I/O (" + e.getLocalizedMessage() + "): " + e.getMessage());
        }
    }

    private void decryptWithDomain(File file, String decryptedFileLocation) {
        try {
            String base64FileContent = readFile(file);

            byte[] data = server.decryptWithDomain(base64FileContent, this.clientModel.getDomainIdentifier());
            String content = new String(data,StandardCharsets.UTF_8);
            writeFile(content,decryptedFileLocation);
        } catch (RemoteException e) {
            System.out.println("Error remote: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error unknown: " + e.getMessage());
        }
    }

    /*---------------------------------------------------------------------------------------------*/

    private String readFile(File file) throws Exception {
        Scanner fileReader = new Scanner(file);

        StringBuilder fileContent = new StringBuilder();
        while (fileReader.hasNextLine())
            fileContent.append(fileReader.nextLine());

        return fileContent.toString();
    }

    private void writeFile(String content, String fileName) throws Exception {
        FileWriter fileWriter = new FileWriter(fileName);
        fileWriter.write(content);
        fileWriter.close();
    }

    /**
     *
     * If client name is empty return False and if client server address return false
     *
     * @return true if input is valid (not empty), else false.
     */
    private boolean validateInput() {
        return !this.clientModel.getClientName().equals("") && !this.clientModel.getServerAddress().equals("");
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-----------------------------------------Window Panels---------------------------------------*/

    /**
     * Generate the startup panel with all the required information.
     *
     * @return the panel with all the information.
     */
    private Panel clientSetupPanel() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(3);

        // Title row
        Label labelTitle = new Label("Client setup.").setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.BEGINNING,
                GridLayout.Alignment.CENTER,
                true,
                false,
                3,
                1));
        panel.addComponent(labelTitle);
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(3));

        // Show host ip row
        Label labelClientAddress = new Label("Client IP: " + clientModel.getClientAddress());
        panel.addComponent(labelClientAddress, GridLayout.createHorizontallyFilledLayoutData(3));
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(3));

        // Client name row
        Label labelClientName = new Label("Type client name:");
        TextBox textBoxClientName = new TextBox().setText("James");
        panel.addComponent(labelClientName, GridLayout.createLayoutData(GridLayout.Alignment.BEGINNING,GridLayout.Alignment.CENTER));
        panel.addComponent(textBoxClientName, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER));

        // Server IP row
        Label labelServerAddress = new Label("Type server ip:");
        TextBox textBoxServerAddress = new TextBox().setText(clientModel.getClientAddress());
        panel.addComponent(labelServerAddress, GridLayout.createLayoutData(GridLayout.Alignment.BEGINNING,GridLayout.Alignment.CENTER));
        panel.addComponent(textBoxServerAddress, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER));
        panel.addComponent(new Separator(Direction.HORIZONTAL).setLayoutData(GridLayout.createHorizontallyFilledLayoutData(3)));

        // Domain ID
        Label labelDomain = new Label("Type domain identifier:");
        TextBox textBoxDomain = new TextBox().setText("1");
        panel.addComponent(labelDomain, GridLayout.createLayoutData(GridLayout.Alignment.BEGINNING,GridLayout.Alignment.CENTER));
        panel.addComponent(textBoxDomain, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER));
        panel.addComponent(new Separator(Direction.HORIZONTAL).setLayoutData(GridLayout.createHorizontallyFilledLayoutData(3)));

        // Next window, validate input
        Button continueButton = new Button("Continue", () -> {
            // Set new data from textBox
            clientModel.setClientName(textBoxClientName.getText());
            clientModel.setServerAddress(textBoxServerAddress.getText());
            clientModel.setDomainIdentifier(Integer.parseInt(textBoxDomain.getText()));

            if (this.validateInput()) {
                try {
                    this.connectToServerAndSubscribe();
                    //TODO: Validate domain ownership.

                    this.clientView.closeWindow();
                    this.clientView.showWindow(this.clientMenuPanel());
                } catch (RemoteException | NotBoundException exception) {
                    this.clientView.showMessageBox("Error", "Can't connect to server.");
                    System.err.println(exception.getMessage());
                }
            } else {
                this.clientView.showMessageBox("Error", "Parameters are invalid.");
            }
        });
        panel.addComponent(continueButton, GridLayout.createHorizontallyFilledLayoutData(1));

        Button closeButton = new Button("Quit", this.clientView::closeScreen);
        panel.addComponent(closeButton, GridLayout.createHorizontallyEndAlignedLayoutData(2));

        return panel;
    }

    /**
     * Generate the menu panel to show, with all the required information.
     *
     * @return the panel to send to window.
     */
    private Panel clientMenuPanel() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(4);

        // Title row
        Label labelTitle = new Label("Client menu.").setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.CENTER,
                GridLayout.Alignment.CENTER,
                true,
                false,
                4,
                1));
        panel.addComponent(labelTitle);
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(4));

        TextBox textBoxFileName = new TextBox("test.enc");
        panel.addComponent(textBoxFileName, GridLayout.createHorizontallyFilledLayoutData(4));

        Label labelDirectory = new Label("No directory.");
        panel.addComponent(labelDirectory, GridLayout.createHorizontallyFilledLayoutData(4));

        Label labelFileName = new Label("No chosen file.");
        panel.addComponent(labelFileName, GridLayout.createHorizontallyFilledLayoutData(4));

        AtomicReference<File> file = new AtomicReference<>();
        AtomicReference<File> directory = new AtomicReference<>();

        Button buttonChooseFile = new Button("Choose file to operate", () -> {
            file.set(this.clientView.showFileDialogWindow());
            labelFileName.setText("Selected file to operate: " + file.get().getName());
        });
        panel.addComponent(buttonChooseFile, GridLayout.createHorizontallyFilledLayoutData(4));

        Button buttonChooseDirectory = new Button("Choose directory", () -> {
            directory.set(this.clientView.showDirectoryDialogWindow());
            labelDirectory.setText(directory.get().getAbsolutePath());
        });
        panel.addComponent(buttonChooseDirectory, GridLayout.createHorizontallyFilledLayoutData(4));

        Button buttonEncrypt = new Button("Encrypt", () -> {
            if (file.get() != null && !textBoxFileName.getText().equals("")) {
                String fileLocation = directory.get().getAbsolutePath() + "/" + textBoxFileName.getText();
                this.clientView.showMessageBox("Information","Encrypting to:\n" + fileLocation);
                this.encryptWithDomain(file.get(), fileLocation);
            }
            else
                this.clientView.showMessageBox("Error","Invalid file.");
        });
        panel.addComponent(buttonEncrypt, GridLayout.createHorizontallyFilledLayoutData(4));

        Button buttonDecrypt = new Button("Decrypt", () -> {
            if (file.get() != null && !textBoxFileName.getText().equals("")) {
                String fileLocation = directory.get().getAbsolutePath() + "/" + textBoxFileName.getText();
                this.clientView.showMessageBox("Information","Decrypting to:\n" + fileLocation);
                this.decryptWithDomain(file.get(), fileLocation);
            }
            else {
                this.clientView.showMessageBox("Error","Invalid file.");
            }
        });
        panel.addComponent(buttonDecrypt, GridLayout.createHorizontallyFilledLayoutData(4));



        Button buttonClose = new Button("Close", this.clientView::closeScreen);
        panel.addComponent(buttonClose, GridLayout.createHorizontallyFilledLayoutData(4));

        return panel;
    }

    /*---------------------------------------------------------------------------------------------*/
}
