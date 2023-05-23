package com.company.entitiesGUI;

import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ClientGUI {

    public ClientGUI() {
        Logger logger = Logger.getLogger("ClientLogger");
        DefaultTerminalFactory terminalFactory = new DefaultTerminalFactory();
        Screen screen = null;

        try {
            screen = terminalFactory.createScreen();
            screen.startScreen();

            // Create a window-based text GUI
            WindowBasedTextGUI textGUI = new MultiWindowTextGUI(screen);
            ClientPanels clientPanels = new ClientPanels();

            // Create windows
            Window windowClientSetup = new BasicWindow("Client setup window");
            Window windowClientMenu = new BasicWindow("Client menu");
            windowClientSetup.setHints(List.of(Window.Hint.CENTERED));
            windowClientMenu.setHints(List.of(Window.Hint.CENTERED));

            List<Window> windowsList = List.of(windowClientSetup, windowClientMenu);

            Panel startupPanel = clientPanels.clientStartupPanel(textGUI, windowsList);
            windowClientSetup.setComponent(startupPanel);

            Panel menuPanel = clientPanels.clientMenuPanel(textGUI, windowsList);
            windowClientMenu.setComponent(menuPanel);

            textGUI.addWindowAndWait(windowClientSetup);
            //textGUI.waitForWindowToClose(windowClientSetup);

        } catch (IOException e) {
            logger.log(Level.WARNING,"IO Exception.");
            e.printStackTrace();
        }
        finally {
            if(screen != null) {
                try {
                    screen.stopScreen();
                    logger.log(Level.INFO,"screen stopping.");
                }
                catch(IOException e) {
                    logger.log(Level.WARNING,"IO Exception.");
                    e.printStackTrace();
                }
            }
        }
    }

}