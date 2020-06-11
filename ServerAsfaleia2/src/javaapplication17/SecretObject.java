package javaapplication17;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


/**
 *
 * @author giorgos
 */

        
import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

public interface SecretObject extends Serializable {
	  PublicKey getSecretMessage();
           byte[] getSecretMessage1();
           public X509Certificate getcert();
           public byte[] getSign();
           
          public BigInteger getmod();
          public BigInteger getgen();
          public byte[] getiv();
            public String Uid();
}
