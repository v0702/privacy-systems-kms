package com.company.mvc.view;

import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.MessageDialog;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;

import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

public class OperatorView {

    private final Logger logger;

    private final WindowBasedTextGUI textGUI;

    private final Window window;

    private final Window secondaryWindow;

    private final Screen screen;

    public OperatorView() throws IOException {
        this.logger = Logger.getLogger("OperatorViewLogger");

        this.screen =  new DefaultTerminalFactory().createScreen();
        this.screen.startScreen();
        this.textGUI = new MultiWindowTextGUI(screen);

        this.window = new BasicWindow("Operator");
        this.window.setHints(List.of(Window.Hint.CENTERED, Window.Hint.EXPANDED));

        this.secondaryWindow = new BasicWindow("Auxiliary window");
        this.window.setHints(List.of(Window.Hint.CENTERED, Window.Hint.EXPANDED));
    }

    public void showMessageBox(String title, String text) {
        MessageDialog.showMessageDialog(textGUI, title, text, MessageDialogButton.Close);
    }

    public void showWindow(Panel panel) {
        try {
            this.window.setComponent(panel);
            this.textGUI.addWindowAndWait(window);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            //this.logger.log(Level.WARNING,"IO Exception:" + e.getMessage());
        }
        finally {
            if(screen != null) {
                try {
                    this.screen.stopScreen();
                    //this.logger.log(Level.INFO,"screen stopping.");
                }
                catch(IOException e) {
                    System.err.println(e.getMessage());
                    //this.logger.log(Level.WARNING,"IO Exception: " + e.getMessage());
                }
            }
        }
    }

    public void showSecondaryWindow(Panel panel) {
        try {
            this.secondaryWindow.setComponent(panel);
            this.textGUI.addWindowAndWait(secondaryWindow);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        finally {
            if(screen != null) {
                try {
                    this.screen.stopScreen();
                }
                catch(IOException e) {
                    System.err.println(e.getMessage());
                }
            }
        }
    }

    public void closeWindow() {
        this.window.close();
    }

    public void closeSecondaryWindow() {
        this.secondaryWindow.close();
    }

    public void switchWindow() {
        textGUI.cycleActiveWindow(false);
    }

    public void closeScreen() {
        if(screen != null) {
            try {
                this.screen.stopScreen();
                //this.logger.log(Level.INFO,"screen stopping.");
            }
            catch(IOException e) {
                System.err.println(e.getMessage());
                //this.logger.log(Level.WARNING,"IO Exception: " + e.getMessage());
            }
        }
        else {
            System.err.println("Screen is null.");
            //this.logger.log(Level.WARNING, "Screen is null.");
        }
    }

}
