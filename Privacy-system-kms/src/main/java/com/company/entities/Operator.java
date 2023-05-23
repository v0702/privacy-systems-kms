package com.company.entities;

import com.company.mvc.controller.OperatorController;
import com.company.mvc.model.OperatorModel;
import com.company.mvc.view.OperatorView;

public class Operator{
    public static void main(String[] args) {
        try {
            OperatorModel operatorModel = new OperatorModel();
            OperatorView operatorView = new OperatorView();

            OperatorController operatorController = new OperatorController(operatorModel, operatorView);

            operatorController.start();

        } catch (Exception exception) {
            System.err.println("-> Exception: " + exception.getMessage());
        }
    }
}
