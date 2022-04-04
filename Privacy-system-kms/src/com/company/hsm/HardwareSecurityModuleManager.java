package com.company.hsm;

import com.company.DomainKeys;

import javax.crypto.SecretKey;
import java.util.Arrays;

public class HardwareSecurityModuleManager {

    //TODO: list or array of hsm's?
    private final static HardwareSecurityModule test_hsm = new HardwareSecurityModule(1024,"RSA");;
    private final static HardwareSecurityModule test_hsm_second = new HardwareSecurityModule(1024,"RSA");
    private static int numberOfHSM = 2;


    public void createDomainKeys(){


        SecretKey freshKey = test_hsm.generateKey(HardwareSecurityModule.AES_KEY_LENGTH_1,"AES");
        byte[] masterKeyToken = test_hsm.encryptAES(test_hsm.generateKey(HardwareSecurityModule.AES_KEY_LENGTH_1,"AES").getEncoded(),freshKey);
        byte[] freshKeyToken = test_hsm.encryptRSA(freshKey.getEncoded(),test_hsm.getPublicKey());
        byte[] freshKeyToken2 = test_hsm.encryptRSA(freshKey.getEncoded(),test_hsm_second.getPublicKey());

        SecretKey[] tokenKeys = new SecretKey[numberOfHSM];
        tokenKeys[0] = DomainKeys.ByteToSecretKey(freshKeyToken,"AES");
        tokenKeys[1] = DomainKeys.ByteToSecretKey(freshKeyToken,"AES");

        DomainKeys domainKeys = new DomainKeys(DomainKeys.ByteToSecretKey(masterKeyToken,"AES"), tokenKeys);
    }

}
