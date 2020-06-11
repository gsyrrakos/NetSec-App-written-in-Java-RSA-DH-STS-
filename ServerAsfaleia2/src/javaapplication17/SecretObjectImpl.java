/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 *
 * @author giorgos
 */
public class SecretObjectImpl implements SecretObject {

    private PublicKey _secretMessage;
    private byte[] secretMessage1;
    private X509Certificate cert;
    private byte[] sign;
    private BigInteger mod;
    private BigInteger gen;
    private byte[] iv;
    private String Uid;

    public BigInteger getmod() {
        return mod;
    }

    public BigInteger getgen() {
        return gen;
    }

    public byte[] getiv() {
        return iv;
    }

    public byte[] getSign() {
        return sign;
    }

    public SecretObjectImpl(PublicKey secretMessage, String uid) {
        _secretMessage = secretMessage;
        Uid = uid;
    }

    public SecretObjectImpl(byte[] secretMessage, String uid) {
        secretMessage1 = secretMessage;
        Uid = uid;
    }

    public SecretObjectImpl(String secretMessage) {
        Uid = secretMessage;
    }

    public SecretObjectImpl(X509Certificate secretMessage, String uid) {
        cert = secretMessage;
        Uid = uid;
    }

    public SecretObjectImpl(PublicKey key, BigInteger secretMessage, BigInteger gen1, byte[] i, String uid) {
        _secretMessage = key;
        mod = secretMessage;
        gen = gen1;
        iv = i;
        Uid = uid;
    }
//public SecretObjectImpl(byte[] secretMessage) {
    //sign = secretMessage;
    //}

    public PublicKey getSecretMessage() {
        return _secretMessage;
    }

    public byte[] getSecretMessage1() {
        return secretMessage1;
    }

    public X509Certificate getcert() {
        return cert;
    }

    @Override
    public String Uid() {
        return Uid;
    }

}
