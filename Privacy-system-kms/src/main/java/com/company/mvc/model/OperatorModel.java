package com.company.mvc.model;

import com.company.utility.CryptographyOperations;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class OperatorModel {

    private String operatorName;
    private String serverAddress;
    private String operatorAddress;
    private KeyPair operatorKeyPair;

    public OperatorModel() {
        this.operatorName = "";
        this.serverAddress = "";
        this.operatorAddress = "";
        this.operatorKeyPair = null;
    }

    public void setOperatorName(String operatorName) {
        this.operatorName = operatorName;
    }

    public void setOperatorAddress(String operatorAddress) {
        this.operatorAddress = operatorAddress;
    }

    public void setServerAddress(String serverAddress) {
        this.serverAddress = serverAddress;
    }

    public void setOperatorKeyPair(KeyPair operatorKeyPair) {
        this.operatorKeyPair = operatorKeyPair;
    }

    public String getOperatorName() {
        return this.operatorName;
    }

    public String getOperatorAddress() {
        return this.operatorAddress;
    }

    public String getServerAddress() {
        return this.serverAddress;
    }

    public KeyPair getKeyPair() {
        return this.operatorKeyPair;
    }

    public PublicKey getPublicKey() {
        return this.operatorKeyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.operatorKeyPair.getPrivate();
    }

    public String getOperatorPrivateKeyBase64() {
        StringBuilder key = new StringBuilder(CryptographyOperations.byteToBase64String(operatorKeyPair.getPrivate().getEncoded()));

        int length = key.length();

        for (int i=0;(i+100)<length;i+=100)
            key.insert(i+100, "\n");

        return key.toString();
    }

    public String getOperatorPublicKeyBase64() {
        StringBuilder key = new StringBuilder(CryptographyOperations.byteToBase64String(operatorKeyPair.getPublic().getEncoded()));

        int length = key.length();

        for (int i=0;(i+100)<length;i+=100)
            key.insert(i+100, "\n");

        return key.toString();
    }

}
