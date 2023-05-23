package com.company.mvc.view;

import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.DirectoryDialogBuilder;
import com.googlecode.lanterna.gui2.dialogs.FileDialogBuilder;
import com.googlecode.lanterna.gui2.dialogs.MessageDialog;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;

import java.io.File;
import java.io.IOException;

import java.util.List;
import java.util.logging.Logger;

// TODO: logging
public class ClientView {

    private final Logger logger;

    private final WindowBasedTextGUI textGUI;

    private final Window window;

    private final Screen screen;

    public ClientView() throws IOException {
        this.logger = Logger.getLogger("ClientViewLogger");

        this.screen =  new DefaultTerminalFactory().createScreen();
        this.screen.startScreen();
        this.textGUI = new MultiWindowTextGUI(screen);

        this.window = new BasicWindow("Client");
        this.window.setHints(List.of(Window.Hint.CENTERED));
    }

    public void showMessageBox(String title, String text) {
        MessageDialog.showMessageDialog(textGUI, title, text, MessageDialogButton.Retry);
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

    public File showFileDialogWindow() {
        try {
            return new FileDialogBuilder().setTitle("Open File").setDescription("Choose a file").setActionLabel("Open").build().showDialog(textGUI);
        } catch (Exception exception) {
            //this.logger.log(Level.WARNING,"IO Exception:" + e.getMessage());
            System.err.println(exception.getMessage());
        }
        return null;
    }

    public File showDirectoryDialogWindow() {
        try {
            return new DirectoryDialogBuilder().setTitle("Select directory").setDescription("Choose a directory").setActionLabel("Select").build().showDialog(textGUI);
        } catch (Exception exception) {
            System.err.println(exception.getMessage());
        }
        return null;
    }

    public void closeWindow() {
        this.window.close();
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
