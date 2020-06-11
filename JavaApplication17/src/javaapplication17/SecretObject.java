/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 *
 * @author giorgos
 */
public interface SecretObject extends Serializable {
	  PublicKey getSecretMessage();
          public byte[] getSecretMessage1();
          public X509Certificate getcert();
          public byte[] getSign();
          public BigInteger getmod();
          public BigInteger getgen();
          public byte[] getiv();
          public String Uid();
}