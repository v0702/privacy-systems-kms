package com.company;

import com.company.hsm.HardwareSecurityModuleManager;

public class Main {

    public static void main(String[] args) {
        HardwareSecurityModuleManager a = new HardwareSecurityModuleManager();

        a.createDomainKeys();
    }
}
