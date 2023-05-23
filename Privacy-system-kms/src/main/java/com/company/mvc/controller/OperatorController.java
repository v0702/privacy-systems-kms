package com.company.mvc.controller;

import com.company.interfaces.ServerInterface;
import com.company.mvc.model.OperatorModel;
import com.company.mvc.view.OperatorView;
import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.table.Table;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

public class OperatorController {

    Logger logger;

    private final OperatorModel operatorModel;
    private final OperatorView operatorView;

    private ServerInterface server;

    /**
     * Constructor for controller.
     * @param operatorModel model with operator data.
     * @param operatorView model with GUI operations.
     * @throws UnknownHostException if problem with localhost IP.
     */
    public OperatorController(OperatorModel operatorModel, OperatorView operatorView) throws UnknownHostException {
        logger = Logger.getLogger("OperatorControllerLogger");

        this.operatorModel = operatorModel;
        this.operatorView = operatorView;

        this.operatorModel.setOperatorAddress(InetAddress.getLocalHost().getHostAddress());
        this.operatorModel.setServerAddress(InetAddress.getLocalHost().getHostAddress());
    }

    public void start() {
        operatorView.showWindow(this.setupPanel());
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-----------------------------------------             ---------------------------------------*/

    private void connectToServer() throws RemoteException, NotBoundException {
        System.setProperty("java.rmi.server.hostname", operatorModel.getServerAddress());
        System.setProperty("sun.rmi.transport.connectionTimeout", "15000"); // Timeout for connection unused
        System.setProperty("sun.rmi.transport.tcp.handshakeTimeout", "1000"); // Timeout for setting up connection
        System.setProperty("sun.rmi.transport.tcp.responseTimeout", "4000"); //Timeout for waiting for response
        Registry registry = LocateRegistry.getRegistry(operatorModel.getServerAddress(), 1099);
        server = (ServerInterface) registry.lookup("server");
    }

    private void subscribeOperatorWithPublicKey() throws RemoteException {
        server.subscribeOperatorWithPublicKey(operatorModel.getOperatorName(), operatorModel.getPublicKey());
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Server functions--------------------------------------*/

    /**
     * Generate a pair of RSA keys, usually done at the startup of the Operator.
     * @throws RemoteException exception from remote server I/O.
     */
    private void generateKeyPair() throws RemoteException {
        operatorModel.setOperatorKeyPair(server.generateKeyPair());
    }

    /**
     *
     * @return boolean return true if success else false.
     * @throws RemoteException exception from remote server I/O.
     */
    private boolean createNewTrust(List<Integer> listHsmID, List<Integer> operatorPublicKeyIndexList) throws RemoteException {
        return server.createNewTrust(listHsmID, operatorPublicKeyIndexList);
    }

    private void createNewHardwareSecurityModule() throws RemoteException {
        server.createNewHardwareSecurityModule();
    }

    private void signTrust() throws RemoteException {
        //TODO:
    }

    private void createNewSymDomain(int trustID) throws RemoteException {
        server.createSymDomain(trustID);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*----------------------------------------Get from server--------------------------------------*/

    /**
     * Get List of HSM ID as string.
     * @return a List of the HSM IDs.
     * @throws RemoteException if server error.
     */
    private List<String> getListHsmIdentifier() throws RemoteException {
        return server.getListHsmIdentifier();
    }

    /**
     * Get a List of Trust ID as String.
     * @return a List of the Trust ID.
     * @throws RemoteException if server error.
     */
    private List<Integer> getListTrustID() throws RemoteException {
        return server.getListTrustID();
    }

    /**
     * Get list of operators name participating in system.
     * @return List of strings of operators names.
     * @throws RemoteException if server error.
     */
    private List<String> getListOperatorName() throws RemoteException {
        return server.getOperatorsNames();
    }

    /**
     * Get HashMap of Operator Name as key and associated public key.
     * @return a hashMap of Operator name (String) and public key (PublicKey).
     * @throws RemoteException if server error.
     */
    private HashMap<String, PublicKey> getOperatorNameAndPublicKey() throws RemoteException {
        return server.getOperatorNameAndPublicKey();
    }

    /**
     * Get a List of operators in a trust.
     * @param trustIdentifier the id of the trust that we want data from.
     * @return a list of operators belonging to a particular trust.
     */
    private List<String> getTrustOperators(int trustIdentifier) throws RemoteException {
        return server.getTrustOperators(trustIdentifier);
    }

    /**
     * Get a List of hardware security modules identifiers in a trust.
     * @param trustIdentifier the id of the trust that we want data from.
     * @return a list of hardware security modules belonging to a particular trust.
     */
    private List<String> getTrustHsm(int trustIdentifier) throws RemoteException {
        return server.getTrustHsm(trustIdentifier);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-----------------------------------------             ---------------------------------------*/

    private boolean validateInput() {
        return !this.operatorModel.getOperatorName().equals("") && !this.operatorModel.getServerAddress().equals("");
    }

    /*---------------------------------------------------------------------------------------------*/
    /*-----------------------------------------Window Panels---------------------------------------*/
    /*---------------------------------------------------------------------------------------------*/
    /*-------------------------------------------------------------------------------*/
    /*-----------------------------------Base Panels---------------------------------*/

    /**
     * Set up the visual panel for the GUI window, includes the buttons and operational code.
     * @return the panel for the window.
     */
    private Panel setupPanel() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(3);

        // Title row
        Label labelTitle = new Label("Operator setup:");
        panel.addComponent(labelTitle, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER, true, false, 3, 1));
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(3));

        // Show host ip row
        Label labelAddress = new Label("Operator IP: " + operatorModel.getOperatorAddress());
        panel.addComponent(labelAddress, GridLayout.createHorizontallyFilledLayoutData(3));
        panel.addComponent(new Separator(Direction.HORIZONTAL).setLayoutData(GridLayout.createHorizontallyFilledLayoutData(3)));

        // Client name row
        Label labelOperatorName = new Label("Type Operator name:");
        panel.addComponent(labelOperatorName, GridLayout.createLayoutData(GridLayout.Alignment.CENTER,GridLayout.Alignment.CENTER));

        TextBox textBoxOperatorName = new TextBox().setText("Operator");
        panel.addComponent(textBoxOperatorName, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER));

        // Server IP row
        Label labelServerAddress = new Label("Type server ip:");
        panel.addComponent(labelServerAddress, GridLayout.createLayoutData(GridLayout.Alignment.CENTER,GridLayout.Alignment.CENTER));

        TextBox textBoxServerAddress = new TextBox().setText(operatorModel.getOperatorAddress());
        panel.addComponent(textBoxServerAddress, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER));
        panel.addComponent(new Separator(Direction.HORIZONTAL).setLayoutData(GridLayout.createHorizontallyFilledLayoutData(3)));

        // Next window, validate input
        Button continueButton = new Button("Continue", () -> {
            // Set new data from textBox
            operatorModel.setOperatorName(textBoxOperatorName.getText());
            operatorModel.setServerAddress(textBoxServerAddress.getText());

            if (this.validateInput()) {
                try {
                    this.connectToServer();
                    this.generateKeyPair();
                    this.subscribeOperatorWithPublicKey();

                    operatorView.showWindow(this.menuPanel());

                } catch (RemoteException | NotBoundException exception) {
                    operatorView.showMessageBox("Error", "Can't connect to server.");
                    System.err.println(exception.getMessage());
                }
            } else {
                operatorView.showMessageBox("Error", "Parameters are invalid.");
            }
        });
        panel.addComponent(continueButton, GridLayout.createHorizontallyFilledLayoutData(1));

        Button closeButton = new Button("Quit", this.operatorView::closeScreen);
        panel.addComponent(closeButton, GridLayout.createHorizontallyEndAlignedLayoutData(2));

        return panel;
    }

    /**
     * Set up the panel with the main menu.
     * @return the panel for the window.
     */
    private Panel menuPanel() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(5);

        // Title row
        Label labelTitle = new Label("Menu");
        panel.addComponent(labelTitle, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER, true, false, 5, 1));
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(5));

        Button buttonTrustMenu = new Button("Trust menu", () -> {
            operatorView.showWindow(this.trustMenuPanel());
        });
        panel.addComponent(buttonTrustMenu, GridLayout.createHorizontallyFilledLayoutData(5));

        Button buttonDomainMenu = new Button("Domain menu", () -> {
            operatorView.showWindow(this.domainMenuPanel());
        });
        panel.addComponent(buttonDomainMenu, GridLayout.createHorizontallyFilledLayoutData(5));

        Button buttonViewMenu = new Button("View menu", () -> {
            operatorView.showWindow(this.viewMenuPanel());
        });
        panel.addComponent(buttonViewMenu, GridLayout.createHorizontallyFilledLayoutData(5));

        Button buttonCreateNewHSM = new Button("Create new HSM", () -> {
            try {
                this.createNewHardwareSecurityModule();
                operatorView.showMessageBox("Information","Sent.");
            } catch (RemoteException exception) {
                operatorView.showMessageBox("Error", "Server error.");
            }
        });
        panel.addComponent(buttonCreateNewHSM, GridLayout.createHorizontallyFilledLayoutData(5));

        Button buttonClose = new Button("Quit", this.operatorView::closeScreen);
        panel.addComponent(buttonClose, GridLayout.createHorizontallyFilledLayoutData(5));

        return panel;
    }

    /*-------------------------------------------------------------------------------*/
    /*------------------------------------Menu Panels--------------------------------*/


    /**
     * Set up the menu for the Trust operations.
     * @return the panel for the window.
     */
    private Panel trustMenuPanel() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(2);

        // Title row
        Label labelTitle = new Label("Trust Menu");
        panel.addComponent(labelTitle, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER, true, false, 2, 1));
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(2));

        // Next window, validate input
        Label labelCreateNewTrust = new Label("Caution").addStyle(SGR.BOLD).setForegroundColor(TextColor.ANSI.RED);
        panel.addComponent(labelCreateNewTrust, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER, false, false, 1, 1));

        Button buttonCreateNewTrust = new Button("Create new trust", () -> {
                operatorView.showMessageBox("Special operation", "Use with care. New trust being created.");
                operatorView.showWindow(this.createTrustPanel());
        });
        panel.addComponent(buttonCreateNewTrust, GridLayout.createHorizontallyFilledLayoutData(1));

        Button buttonUpdateTrust = new Button("Update trust", () -> {
            operatorView.showWindow(this.getTrustView());
            //operatorView.showSecondaryWindow(this.something());
        });
        panel.addComponent(buttonUpdateTrust, GridLayout.createHorizontallyFilledLayoutData(2));

        Button buttonOperatorSignTrust = new Button("Operator sign trust", () -> {
            // TODO: View trusts where operator is mentioned
            // TODO: Select it and sign it
            // TODO: Send signature
        });
        panel.addComponent(buttonOperatorSignTrust, GridLayout.createHorizontallyFilledLayoutData(2));

        Button buttonSignTrust = new Button("Sign trust (HSM)", () -> {
            // TODO: View trusts where operator is mentioned
            // TODO: Get it
            // TODO: Sign it
            // TODO: Send signature
        });
        panel.addComponent(buttonSignTrust, GridLayout.createHorizontallyFilledLayoutData(2));

        Button buttonReturn = new Button("Return", () -> {
            operatorView.showWindow(menuPanel());
        });
        panel.addComponent(buttonReturn, GridLayout.createHorizontallyFilledLayoutData(2));

        return panel;
    }

    private Panel domainMenuPanel() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(2);

        // Title row
        Label labelTitle = new Label("Domain Menu");
        panel.addComponent(labelTitle, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER, true, false, 2, 1));
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(2));

        Label labelTrustRadioBoxTitle = new Label("Select trust for domain:");
        panel.addComponent(labelTrustRadioBoxTitle, GridLayout.createHorizontallyFilledLayoutData(2));
        RadioBoxList<Integer> radioBoxList = new RadioBoxList<>();
        List<Integer> listTrustIdentifiers = new ArrayList<>();
        try {
            listTrustIdentifiers = this.getListTrustID();
        } catch (RemoteException exception) {
            operatorView.showMessageBox("Error", "Server error.");
        }
        for (int trustID : listTrustIdentifiers)
            radioBoxList.addItem(trustID);
        panel.addComponent(radioBoxList, GridLayout.createHorizontallyFilledLayoutData(3));

        Button buttonCreateNewDomain = new Button("Create new symmetric domain", () -> {
            try {
                int domainID = server.createSymDomain(radioBoxList.getCheckedItem());
                if (domainID == -1)
                    operatorView.showMessageBox("Error","Domain was not created.");
                else
                    operatorView.showMessageBox("Information","Domain was created with id: "+ domainID);

                operatorView.showWindow(viewMenuPanel());
            } catch (RemoteException e) {
                operatorView.showMessageBox("Error", "Server error.");
            }
        });
        panel.addComponent(buttonCreateNewDomain, GridLayout.createHorizontallyFilledLayoutData(1));

        Button buttonReturn = new Button("Return", () -> {
            operatorView.showWindow(menuPanel());
        });
        panel.addComponent(buttonReturn, GridLayout.createHorizontallyFilledLayoutData(2));

        return panel;
    }

    /**
     * Pane for the menu with data viewing options.
     * @return the panel for the window
     */
    private Panel viewMenuPanel() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(5);

        // Title row
        Label labelTitle = new Label("View menu");
        panel.addComponent(labelTitle, GridLayout.createLayoutData(GridLayout.Alignment.CENTER, GridLayout.Alignment.CENTER, true, false, 5, 1));
        panel.addComponent(new Separator(Direction.HORIZONTAL), GridLayout.createHorizontallyFilledLayoutData(5));

        Button buttonShowOperatorKeyPair = new Button("Show operator key pair", () -> {
            operatorView.showMessageBox("PublicKey", operatorModel.getOperatorPublicKeyBase64());
            operatorView.showMessageBox("PrivateKey", operatorModel.getOperatorPrivateKeyBase64());
        });
        panel.addComponent(buttonShowOperatorKeyPair, GridLayout.createHorizontallyFilledLayoutData(5));

        Button buttonViewTrust = new Button("View trusts", () -> {
            try {
                List<Integer> listTrustID = this.getListTrustID();
                Table<String> table = new Table<>("Trust ID","Operators", "HSM IDs");

                for (Integer trustID : listTrustID) {
                    List<String> listTrustOperators = this.getTrustOperators(trustID);
                    StringBuilder stringBuilderNames = new StringBuilder();
                    for (String name : listTrustOperators)
                        stringBuilderNames.append(name).append("\n");

                    List<String> listTrustHsmID = this.getTrustHsm(trustID);
                    StringBuilder stringBuilderHsm = new StringBuilder();
                    for (String hsmID : listTrustHsmID)
                        stringBuilderHsm.append(hsmID).append("\n");

                    table.getTableModel().addRow(trustID.toString(), stringBuilderNames.toString(), stringBuilderHsm.toString());
                }
                Panel panelTable = new Panel();
                panelTable.addComponent(table);


                Button buttonReturn = new Button("Return", () -> {
                    operatorView.closeSecondaryWindow();
                    operatorView.showWindow(viewMenuPanel());
                });
                panelTable.addComponent(buttonReturn);

                operatorView.showSecondaryWindow(panelTable);

            } catch (RemoteException exception) {
                operatorView.showMessageBox("Error", "Server error.");
            }
        });
        panel.addComponent(buttonViewTrust, GridLayout.createHorizontallyFilledLayoutData(3));

        Button buttonViewDomains = new Button("View domains", () -> {

        });
        panel.addComponent(buttonViewDomains, GridLayout.createHorizontallyFilledLayoutData(3));

        Button buttonReturn = new Button("Return", () -> {
            operatorView.showWindow(menuPanel());
        });
        panel.addComponent(buttonReturn, GridLayout.createHorizontallyFilledLayoutData(3));

        return panel;
    }

    /*-------------------------------------------------------------------------------*/
    /*-----------------------------------Trust Panels--------------------------------*/

    /**
     * Panel for trust parameters selection for new trust creation.
     * @return the panel for the window.
     */
    private Panel createTrustPanel() {
        Panel panel = new Panel(new GridLayout(4));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(4);

        Label labelTitle = new Label("Select HSM ID and operator for trust:");
        panel.addComponent(labelTitle, GridLayout.createHorizontallyFilledLayoutData(4));

        //Prep check box and get data -> HSM
        CheckBoxList<String> checkBoxListHsm = new CheckBoxList<>();
        List<String> hsmNamesList = new ArrayList<>();
        try {
            hsmNamesList = this.getListHsmIdentifier();
        } catch (RemoteException exception) {
            operatorView.showMessageBox("Error", "Server error getting HsmNameList.");
        }
        // fill checkbox with data
        for (String hsmName : hsmNamesList)
            checkBoxListHsm.addItem(hsmName);
        panel.addComponent(checkBoxListHsm, GridLayout.createHorizontallyFilledLayoutData(2));
        //----------------

        //Prep check box and get data -> Operator

        CheckBoxList<String> checkBoxListOperator = new CheckBoxList<>();
        List<String> operatorNamesList = new ArrayList<>();
        try {
            operatorNamesList = this.getListOperatorName();
        } catch (RemoteException exception) {
            operatorView.showMessageBox("Error", "Server error getting HsmNameList.");
        }
        // fill checkbox with data
        for (String operatorName : operatorNamesList)
            checkBoxListOperator.addItem(operatorName);
        panel.addComponent(checkBoxListOperator, GridLayout.createHorizontallyFilledLayoutData(2));
        //----------------

        Button buttonCreateNewTrust = new Button("Continue", () -> {
            try {
                List<String> listSelectedHsm = checkBoxListHsm.getCheckedItems();
                List<Integer> listHsmId = new ArrayList<>();
                for (String item : listSelectedHsm)
                    listHsmId.add(Integer.valueOf(item));

                List<String> listSelectedOperators = checkBoxListOperator.getCheckedItems();
                List<String> listOperatorName = this.getListOperatorName();
                List<Integer> operatorPublicKeyIndexList = new ArrayList<>();
                for (String operatorName : listSelectedOperators) {
                    operatorPublicKeyIndexList.add(listOperatorName.indexOf(operatorName));
                }

                boolean status = this.createNewTrust(listHsmId, operatorPublicKeyIndexList);
                if (status)
                    operatorView.showMessageBox("Status", "Success creating new trust.");
                else
                    operatorView.showMessageBox("Status", "Failure creating new trust.");

                operatorView.showWindow(menuPanel());

            } catch (RemoteException exception) {
                operatorView.showMessageBox("Error", "Server error.");
                System.err.println(exception.getMessage());
            }
        });
        panel.addComponent(buttonCreateNewTrust, GridLayout.createHorizontallyFilledLayoutData(4));

        Button buttonReturn = new Button("Return", () -> {
           operatorView.showWindow(trustMenuPanel());
        });
        panel.addComponent(buttonReturn, GridLayout.createHorizontallyFilledLayoutData(4));

        return panel;
    }

    private Panel updateTrustPanel(AtomicInteger selectedTrust) {
        Panel panel = new Panel(new GridLayout(4));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(6);

        Label labelTitle = new Label("Select Operator and HSM for trust:");
        panel.addComponent(labelTitle, GridLayout.createHorizontallyFilledLayoutData(6));

        //----Operator info----
        CheckBoxList<String> checkBoxListOperator = new CheckBoxList<>();
        HashMap<String, PublicKey> operatorNameAndPublicKey = new HashMap<>();
        List<String> listTrustOperators = new ArrayList<>();
        try {
            operatorNameAndPublicKey = this.getOperatorNameAndPublicKey();
            listTrustOperators = this.getTrustOperators(selectedTrust.get());
        } catch (RemoteException exception) {
            operatorView.showMessageBox("Error", "Server error.");
        }
        // fill checkbox with data, only the ones not in trust
        for (String operatorName : operatorNameAndPublicKey.keySet()) {
            if (listTrustOperators.contains(operatorName))
                continue;
            checkBoxListOperator.addItem(operatorName);
        }
        panel.addComponent(checkBoxListOperator, GridLayout.createHorizontallyFilledLayoutData(3));
        //-----------------

        //-----HSM info----
        CheckBoxList<String> checkBoxListHsm = new CheckBoxList<>();
        List<String> listHsmID = new ArrayList<>();
        List<String> listTrustHsmID = new ArrayList<>();
        try {
            listHsmID = this.getListHsmIdentifier();
            listTrustHsmID = this.getTrustHsm(selectedTrust.get());

        } catch (RemoteException exception) {
            operatorView.showMessageBox("Error", "Server error.");
        }
        // fill checkbox with data, only the ones not in trust
        for (String hsmID : listHsmID) {
            if (listTrustHsmID.contains(hsmID))
                continue;
            checkBoxListHsm.addItem(hsmID);
        }
        panel.addComponent(checkBoxListHsm);
        //-----------------

        Button buttonUpdateTrust = new Button("Continue", () -> {
            try {
                List<String> listSelectedOperatorNames = checkBoxListOperator.getCheckedItems();
                List<String> listSelectedHsmID = checkBoxListHsm.getCheckedItems();
                //TODO: call update trust on HSM.


            } catch (Exception exception) {
                operatorView.showMessageBox("Error", "Server error.");
                System.err.println(exception.getMessage());
            }
        });
        panel.addComponent(buttonUpdateTrust, GridLayout.createHorizontallyFilledLayoutData(6));

        Button buttonReturn = new Button("Get", () ->{
            operatorView.showWindow(menuPanel());
        });
        panel.addComponent(buttonReturn, GridLayout.createHorizontallyFilledLayoutData(6));

        return panel;
    }

    private Panel getTrustView() {
        Panel panel = new Panel(new GridLayout(2));
        GridLayout gridLayout = (GridLayout) panel.getLayoutManager();
        gridLayout.setHorizontalSpacing(3);

        //------Select Trust------
        Label labelTrustRadioBoxTitle = new Label("Select trust:");
        panel.addComponent(labelTrustRadioBoxTitle, GridLayout.createHorizontallyFilledLayoutData(3));
        RadioBoxList<Integer> radioBoxList = new RadioBoxList<>();

        List<Integer> listTrustIdentifiers = new ArrayList<>();
        try {
            listTrustIdentifiers = this.getListTrustID();
        } catch (RemoteException exception) {
            operatorView.showMessageBox("Error", "Server error.");
        }

        for (int trustID : listTrustIdentifiers) {
            radioBoxList.addItem(trustID);
        }
        panel.addComponent(radioBoxList, GridLayout.createHorizontallyFilledLayoutData(3));

        AtomicInteger selectedTrust = new AtomicInteger(-1);
        Button buttonReturn = new Button("Get", () ->{
            selectedTrust.set(radioBoxList.getCheckedItem());
            operatorView.showWindow(updateTrustPanel(selectedTrust));
        });
        panel.addComponent(buttonReturn, GridLayout.createHorizontallyFilledLayoutData(3));
        //---------------------

        return panel;
    }

    /*-------------------------------------------------------------------------------*/
    /*---------------------------------Domain Panels---------------------------------*/



    /*-------------------------------------------------------------------------------*/
    /*------------------------------------View Panels--------------------------------*/



    /*-------------------------------------------------------------------------------*/
    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------------------------------------------------------------*/
}
