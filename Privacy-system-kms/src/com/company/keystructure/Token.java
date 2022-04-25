package com.company.keystructure;

/**
 * An encrypted key, usually with another key, stored as a byte array
 */
public class Token {
    private final byte[] key;

    public Token(byte [] key) {
        this.key = key;
    }

    public byte[] getEncode(){
        return this.key;
    }
}
