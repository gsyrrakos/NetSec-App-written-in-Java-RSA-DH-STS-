/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.data;

/**
 *
 * @author giorgos
 */
public class Aes {
    public  SecretKey decrypt(byte[] text, PrivateKey key) {
    SecretKey key1=null;
        byte[] dectyptedText = null;
        Cipher cipher=null;
    try {
      // get an RSA cipher object and print the provider
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

      // decrypt the text using the private key
      cipher.init(Cipher.DECRYPT_MODE, key);
      //dectyptedText = cipher.doFinal(text);
 key1 = new SecretKeySpec ( cipher.doFinal(text), "AES" );
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return key1;
  }

     public  byte[] encrypt(byte[] text, PublicKey key) {
    byte[] cipherText = null;
    try {
      // get an RSA cipher object and print the provider
      final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      // encrypt the plain text using the public key
      cipher.init(Cipher.ENCRYPT_MODE, key);
      cipherText = cipher.doFinal(text);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return cipherText;
  } 
}
