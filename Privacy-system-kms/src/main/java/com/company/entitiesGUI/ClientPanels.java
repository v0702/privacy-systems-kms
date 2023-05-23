package com.company.entitiesGUI;

import com.company.interfaces.ServerInterface;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.MessageDialog;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.List;

public class ClientPanels {


    private String clientIp;
    private TextBox clientNameTextBox;
    private TextBox ipServerTextBox;

    public ClientPanels() throws UnknownHostException {

    }

    public Panel clientStartupPanel(WindowBasedTextGUI textGUI, List<Window> windowsList) throws UnknownHostException {
        Panel contentPanel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) contentPanel.getLayoutManager();
        gridLayout.setHorizontalSpacing(3);

        // Title row
        Label title = new Label("Client setup:").setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.BEGINNING,
                GridLayout.Alignment.CENTER,
                true,
                false,
                3,
                1));
        contentPanel.addComponent(title);
        contentPanel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(3));

        // Show host ip row
        clientIp = InetAddress.getLocalHost().getHostAddress();
        Label clientIpLabel = new Label("Client IP: " + clientIp);
        contentPanel.addComponent(clientIpLabel, GridLayout.createHorizontallyFilledLayoutData(3));
        contentPanel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(3));

        // Client name row
        Label clientNameLabel = new Label("Type client name:");
        clientNameTextBox = new TextBox().setText("James");
        contentPanel.addComponent(clientNameLabel, GridLayout.createLayoutData(GridLayout.Alignment.BEGINNING,GridLayout.Alignment.CENTER));
        contentPanel.addComponent(clientNameTextBox, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER));

        // Server IP row
        Label ipServerLabel = new Label("Type server ip:");
        ipServerTextBox = new TextBox().setText("127.0.1.1");
        contentPanel.addComponent(ipServerLabel, GridLayout.createLayoutData(GridLayout.Alignment.BEGINNING,GridLayout.Alignment.CENTER));
        contentPanel.addComponent(ipServerTextBox, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER));
        contentPanel.addComponent(new Separator(Direction.HORIZONTAL).setLayoutData(GridLayout.createHorizontallyFilledLayoutData(3)));

        // Next window, validate input
        Button continueButton = new Button("Continue", () -> {
            if (this.validateClientStartup()) {
                try {
                        this.connectServer();
                        textGUI.removeWindow(windowsList.get(0));
                        textGUI.addWindowAndWait(windowsList.get(1));
                } catch (NotBoundException | RemoteException e) {
                    throw new RuntimeException(e);
                }
            }
            else {
                MessageDialog.showMessageDialog(textGUI, "Info", "Parameters are invalid.", MessageDialogButton.OK);
            }
        });
        contentPanel.addComponent(continueButton, GridLayout.createHorizontallyFilledLayoutData(1));

        Button closeButton = new Button("Quit", windowsList.get(0)::close);
        contentPanel.addComponent(closeButton, GridLayout.createHorizontallyEndAlignedLayoutData(2));

        return contentPanel;
    }

    public Panel clientMenuPanel(WindowBasedTextGUI textGUI, List<Window> windowsList) {
        Panel menuPanel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) menuPanel.getLayoutManager();
        gridLayout.setHorizontalSpacing(3);

        Label testLabel = new Label("Some text");
        menuPanel.addComponent(testLabel, GridLayout.createHorizontallyFilledLayoutData(3));

        Button continueButton = new Button("Switch window", () -> {
            if (!this.getClientName().equals("") && !this.getIpServer().equals("")) {
                textGUI.removeWindow(windowsList.get(1));
                textGUI.addWindowAndWait(windowsList.get(0));
            }
        }
        );
        menuPanel.addComponent(continueButton, GridLayout.createHorizontallyFilledLayoutData(2));

        return menuPanel;
    }

    private boolean validateClientStartup() {
        if (ipServerTextBox.getText().equals(""))
            ipServerTextBox.setText(this.getClientIp());

        return !clientNameTextBox.getText().equals("");
    }

    private void connectServer() throws NotBoundException, RemoteException {
        Registry registry;
        ServerInterface server = null;

        System.setProperty("java.rmi.server.hostname", this.getIpServer());
        registry = LocateRegistry.getRegistry(this.getIpServer(), 1099);
        server = (ServerInterface) registry.lookup("server");
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getClientName() {
        return clientNameTextBox.getText();
    }

    public String getIpServer() {
        return ipServerTextBox.getText();
    }

}