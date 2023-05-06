package com.company.utility;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * General usage Cryptographic and Hashing functions.
 */
public class CryptographyOperations {

    public static int AES_KEY_LENGTH_1 = 128;
    public static int AES_KEY_LENGTH_2 = 192;
    public static int AES_KEY_LENGTH_3 = 256;

    public static int RSA_KEY_LENGTH_2 = 2048;

    public static String KEY_GENERATOR_ALGORITHM_AES = "AES";
    public static String KEY_GENERATOR_ALGORITHM_RSA = "RSA";
    public static String HASH_ALGORITHM_1 = "SHA-512/256";

    private static final int BOCK_SIZE = 16;

    /**
     * using /dev/urandom & SHA1PRNG algorithm
     */
    private final SecureRandom random = new SecureRandom();


    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------Block encryption---------------------------------------*/

    /**
     * Function to encrypt byte array data using AES
     * @param data byte array of the data to encrypt
     * @param key of type SecretKey, the key to use for encryption
     * @return finaCipher, of byte array type, or null if exception caught
     */
    protected byte[] encryptAES(byte[] data, SecretKey key) {
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
            System.err.println("-> Exception: Error encrypting data (AES): " + e.getMessage());
            return null;
        }
    }

    /**
     * Function to decrypt byte array encrypted data using AES
     * @param encryptedData byte array of the encrypted data to decrypt
     * @param key of type SecretKey, the key to use for decryption
     * @return the decrypted data in byte array format, or null if exception caught
     */
    protected byte[] decryptAES(byte[] encryptedData,SecretKey key) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(encryptedData,0,BOCK_SIZE);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return cipher.doFinal(encryptedData,BOCK_SIZE,encryptedData.length - BOCK_SIZE);
        } catch (Exception e) {
            System.err.println("-> Exception: Error decrypting data (AES): " + e.getMessage());
            return null;
        }
    }

    /**
     * Function that generates a random IV of BLOCK_SIZE size.
     * @return IvParameterSpec
     */
    private IvParameterSpec generateIv() {
        byte[] iv = new byte[BOCK_SIZE];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /*---------------------------------------------------------------------------------------------*/
    /*------------------------------------Public key encryption------------------------------------*/


    /**
     * <p>
     * Function to encrypt using RSA
     * </p>
     * @param data byte array of the data to encrypt
     * @param publicKey of type PublicKey, the key to use for encryption
     * @return finaCipher, of byte array type, or null if exception caught
     */
    protected byte[] encryptRSA(byte[] data, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        }
        catch (Exception e){
            System.err.println("-> Exception: Error encrypting data (RSA): " + e.getMessage());
            return null;
        }
    }

    /**
     * <p>
     * Function that decrypts using RSA
     * </p>
     * @param encryptedData byte array of the encrypted data to decrypt
     * @param privateKey of type PrivateKey, the key to use for decryption
     * @return the decrypted data in byte array format, or null if exception caught
     */
    protected byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedData);
        }
        catch (Exception e){
            System.err.println("-> Exception: Error decrypting data (RSA): " + e.getMessage());
            return null;
        }
    }

    /**
     * <p>
     * Function to sign using RSA
     * </p>
     * @param data byte array of the data to encrypt
     * @param privateKey of type PrivateKey, the key to use for encryption
     * @return signature, of byte array type, or null if exception caught
     */
    protected byte[] signatureRSA(byte[] data, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
        }
        catch (Exception e){
            System.err.println("-> Exception: Error signing data (RSA): " + e.getMessage());
            return null;
        }
    }

    /**
     * <p>
     * Verify the signature by RSA cryptography
     * </p>
     * @param data the byte array of the data to verify
     * @param signature the byte array of the signature of the data
     * @param publicKey the public key to use to verify the signature
     * @return true if signature is valid else false
     */
    protected boolean checkSignatureRSA(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(publicKey);
            signer.update(data);
            return signer.verify(signature);
        }
        catch (Exception e){
            System.err.println("-> Exception: Error checking signature data (RSA): " + e.getMessage());
            return false;
        }
    }

    /*---------------------------------------------------------------------------------------------*/
    /*----------------------------------------Hash operations--------------------------------------*/

    /**
     * TODO: public method need fix?
     * Function that hash data using a specified algorithm
     * @param data the byte array data to hash
     * @param algorithm string of the hash algorithm to use
     * @return hash of the data in byte array format
     */
    public byte[] hashSum(byte[] data,String algorithm){
        try {
            MessageDigest messageDigestInstance = MessageDigest.getInstance(algorithm);
            messageDigestInstance.update(data);
            return messageDigestInstance.digest();
        } catch (Exception e) {
            System.err.println("-> Exception: Error creating hash: " + e.getMessage());
            return null;
        }
    }

    /*---------------------------------------------------------------------------------------------*/
    /*--------------------------------------Keys generations---------------------------------------*/

    /**
     * Function to randomly generate keys
     * @param keySize size in bits of the key
     * @param algorithm for which algorithm the key is
     * @return SecretKey randomly generated
     */
    protected SecretKey generateKey(int keySize, String algorithm){


        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(keySize,random);
            return keyGen.generateKey();
        } catch (Exception e) {
            System.err.println("-> Exception: Error generating key: " + e.getMessage());
            return null;
        }
    }

    /**
     * Function to randomly generate key pairs
     * @param keySize size in bits of the key
     * @param algorithm for which algorithm the key is
     * @return KeyPair
     */
    protected KeyPair generateKeyPair(int keySize, String algorithm){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
            keyGen.initialize(keySize,random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("-> Exception: Error generating key pair: " + e.getMessage());
            return null;
        }
    }

    /*---------------------------------------------------------------------------------------------*/
    /*---------------------------------------Keys conversions--------------------------------------*/

    /**
     * Convert from SecretKey to byte array
     * @param key the secret key to convert
     * @return byte array of the key
     */
    protected static byte[] secretKeyToByte(SecretKey key) {
        return key.getEncoded();
    }

    /**
     * Convert from byte array to SecretKey
     * @param key the byte array key to convert to SecretKey
     * @param algorithm the Spec of the key to convert for SecretKeySpec
     * @return SecretKey type from byte array
     */
    protected static SecretKey byteToSecretKey(byte[] key, String algorithm){
        return new SecretKeySpec(key,algorithm);
    }

    /**
     * Convert from PrivateKey to byte array
     * @param key the private key to convert
     * @return byte array of the key
     */
    protected static byte[] privateKeyToByte(PrivateKey key) {
        return key.getEncoded();
    }

    /**
     * Convert from byte array to PrivateKey
     * @param key the byte array key to convert to PrivateKey
     * @param algorithm the Spec of the key to convert for getInstance
     * @return PrivateKey type from byte array
     */
    protected static PrivateKey byteToPrivateKey(byte[] key, String algorithm){
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(key));
        } catch (Exception e) {
            return null;
        }
    }

    /*---------------------------------------------Other-------------------------------------------*/

    /**
     * Function to get the byte array of a serializable object
     * @param object - the object to transform to byte array
     * @return byte array or null of Exception
     */
    public static byte[] objectToByte(Serializable object){
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(object);
            oos.flush();
            byte[] byteArray = baos.toByteArray();

            baos.close();
            oos.close();
            return byteArray;
        } catch (Exception e){
            System.err.println("-> Exception: objectToByte - Error getting object to byte array: " + e.getMessage());
            return null;
        }
    }

    public static String getHashIdentifier(Object object) {
        try {
            MessageDigest messageDigestInstance = MessageDigest.getInstance(HASH_ALGORITHM_1);
            messageDigestInstance.update(intToBytes(object.hashCode()));
            byte[] hash = messageDigestInstance.digest();
            return encodeHexString(hash);
        } catch (Exception e) {
            System.err.println("-> Exception: Error creating hash: " + e.getMessage());
            return "**ERROR**"; //TODO: FIX
        }
    }

    public static String encodeHexString(byte[] byteArray) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte b : byteArray) {
            hexStringBuilder.append(byteToHex(b));
        }
        return hexStringBuilder.toString();
    }

    public static String byteToBase64String(byte[] byteArrayData) {
        return Base64.getEncoder().encodeToString(byteArrayData);
    }

    public static byte[] base64ToByte(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    private static byte[] intToBytes(int data) {
        return new byte[] {
                (byte)((data >> 24) & 0xff),
                (byte)((data >> 16) & 0xff),
                (byte)((data >> 8) & 0xff),
                (byte)((data) & 0xff),
        };
    }

    private static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    /*---------------------------------------------------------------------------------------------*/
}
