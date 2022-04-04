package com.company.hsm;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;


/*
* @author victor
*/
public class HardwareSecurityModule {

    private KeyPair pair;
    private SecureRandom random;
    private int keySize;

    public static int AES_KEY_LENGTH_1 = 128;
    public static int AES_KEY_LENGTH_2 = 192;
    public static int AES_KEY_LENGTH_3 = 256;

    private static final int BOCK_SIZE = 16;

    //TODO: fix throw
    public HardwareSecurityModule(int keySize, String algorithm){
        this.keySize = keySize;
        this.random = new SecureRandom(); //using /dev/urandom & SHA1PRNG algorithm
        pair = generateKeyPair(this.keySize,algorithm);
        if (pair == null)
            pair = generateKeyPair(2048,"RSA");
    }

    private IvParameterSpec generateIv() {
        byte[] iv = new byte[BOCK_SIZE];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public byte[] encryptAES(byte[] data, SecretKey key) {
        try {
            IvParameterSpec ivParameterSpec = generateIv();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] cipherBytes = cipher.doFinal(data);
            byte[] finalCipher = new byte[cipherBytes.length+ivParameterSpec.getIV().length];
            System.arraycopy(ivParameterSpec.getIV(),0,finalCipher,0,ivParameterSpec.getIV().length);
            System.arraycopy(cipherBytes,0,finalCipher,ivParameterSpec.getIV().length,cipherBytes.length);
            return finalCipher;
        } catch (Exception e) {
            System.out.println("Error encrypting data (AES): " + e.getMessage());
            return null;
        }
    }

    public byte[] decryptAES(byte[] encryptedData,SecretKey key) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(encryptedData,0,BOCK_SIZE);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return cipher.doFinal(encryptedData,BOCK_SIZE,encryptedData.length - BOCK_SIZE);
        } catch (Exception e) {
            System.out.println("Error decrypting data (AES): " + e.getMessage());
            return null;
        }
    }

    public byte[] encryptRSA(byte[] data,PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        }
        catch (Exception e){
            System.out.println("Error encrypting data (RSA): " + e.getMessage());
            return null;
        }
    }

    public byte[] decryptRSA(byte[] encryptedData,PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        }
        catch (Exception e){
            System.out.println("Error decrypting data (RSA): " + e.getMessage());
            return null;
        }
    }

    public byte[] encryptRSA(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.pair.getPublic());
            return cipher.doFinal(data);
        }
        catch (Exception e){
            System.out.println("Error encrypting data (RSA): " + e.getMessage());
            return null;
        }
    }

    public byte[] decryptRSA(byte[] encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.pair.getPrivate());
            return cipher.doFinal(encryptedData);
        }
        catch (Exception e){
            System.out.println("Error decrypting data (RSA): " + e.getMessage());
            return null;
        }
    }

    public SecretKey generateKey(int keySize, String algorithm){
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(keySize,random);
            return keyGen.generateKey();
        } catch (Exception e) {
            System.out.println("Error generating key: " + e.getMessage());
            return null;
        }
    }

    public KeyPair generateKeyPair(int keySize, String algorithm){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
            keyGen.initialize(keySize,random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error generating key pair: " + e.getMessage());
            return null;
        }
    }

    //TODO: should prob not exist, I dont think pk should leave the machine
    public PrivateKey getPrivateKey() {
        return pair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return pair.getPublic();
    }

    public int getKeySize() {
        return keySize;
    }
}
