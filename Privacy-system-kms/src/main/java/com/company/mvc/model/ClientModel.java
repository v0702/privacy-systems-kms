package com.company.mvc.model;

public class ClientModel {

    private String clientName;
    private String serverAddress;
    private String clientAddress;
    private int domainIdentifier;

    public ClientModel() {
        this.clientName = "";
        this.clientAddress = "";
        this.serverAddress = "";
        this.domainIdentifier = -1;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public void setClientAddress(String clientAddress) {
        this.clientAddress = clientAddress;
    }

    public void setServerAddress(String serverAddress) {
        this.serverAddress = serverAddress;
    }

    public void setDomainIdentifier(int domainIdentifier) {
        this.domainIdentifier = domainIdentifier;
    }

    public String getClientName() {
        return clientName;
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public int getDomainIdentifier() {
        return domainIdentifier;
    }
}
