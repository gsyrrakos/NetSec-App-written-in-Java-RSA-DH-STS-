/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.UUID;

/**
 *
 * @author giorgos
 */
public class DiffieHellman {

    public static String generateString() {
        String uuid = UUID.randomUUID().toString();
        return "uuid = " + uuid;
    }

    String path = "C:\\Users\\giorgos\\Music\\JavaApplication17";

    public void startParty(HashMap<String, String> hmap) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, ClassNotFoundException, NoSuchProviderException, SignatureException, Exception {
        String server = "localhost";

        System.out.println("Receiver Started");
        Certificates cer = new Certificates();
        //cer.star();

        //exw stin diathesi mou ta pisopoitika tis ca ki tou xrhsth
        //tou xrhsth to thelw dioti periexi ki to public key tou 
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream fs = new FileInputStream(path + "\\clientCert.jks");
        keystore.load(fs, "10212433".toCharArray());

        KeyStore keystore1 = KeyStore.getInstance("JKS");
        FileInputStream fs1 = new FileInputStream(path + "\\edw.jks");
        keystore1.load(fs1, "10212433".toCharArray());
//ftiaxnw to secket epikoinwnias
        Socket clientSocket = new Socket("127.0.0.1", 12348);
        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());

        SecretObject decryptedSecretObject = (SecretObject) ois.readObject();
        if (hmap.isEmpty()) {
            hmap.put(decryptedSecretObject.Uid(), decryptedSecretObject.Uid());
        } else if (hmap.containsKey(decryptedSecretObject.Uid())) {
            clientSocket.close();
        } else {
            hmap.put(decryptedSecretObject.Uid(), decryptedSecretObject.Uid());
        }
        X509Certificate jsCert = decryptedSecretObject.getcert();
        //elenxei an exoun upogegrafei apo tin ca
        if (!cer.Trust(jsCert, keystore1.getCertificate("cert").getPublicKey())) {
            clientSocket.close();
        }
        System.out.println("edw einai to public key tou server" + jsCert.getPublicKey());
        SecretObject secretObject = new SecretObjectImpl((X509Certificate) keystore.getCertificate("cert"), generateString());
        oos.writeObject(secretObject);
        oos.flush();
        Certificates ca = new Certificates();
        Signature signatureProvider = null;

        signatureProvider = Signature.getInstance("SHA1WithRSA");
        //fortwnw ki topothetw to private key tis CA

//edw
        signatureProvider.initSign(ca.loadPrivateKey(path + "\\id_rsaclient"));

        // signatureProvider.initSign(ce.loadPrivateKey("C:\\Users\\giorgos\\Music\\JavaApplication17\\id_rsaclient"));
        byte[] signature = signatureProvider.sign();

        //=========================================================
        signatureProvider.update(jsCert.getPublicKey().getEncoded());
        //signatureProvider.update(pkServer.getEncoded());

        SecretObject secretObject5 = new SecretObjectImpl(signatureProvider.sign(), generateString());
        oos.writeObject(secretObject5);
        oos.flush();

        SecretObject decryptedSecretObject6 = (SecretObject) ois.readObject();
       //check gia replay
        if (hmap.isEmpty()) {
            hmap.put(decryptedSecretObject6.Uid(), decryptedSecretObject6.Uid());
        } else if (hmap.containsKey(decryptedSecretObject6.Uid())) {
            clientSocket.close();
        } else {
            hmap.put(decryptedSecretObject6.Uid(), decryptedSecretObject6.Uid());
        }
        
        //verify tis upografis
        
        Signature clientSign = Signature.getInstance("SHA1withRSA");
        clientSign.initVerify(jsCert.getPublicKey());
        clientSign.update(keystore.getCertificate("cert").getPublicKey().getEncoded());
        if (!clientSign.verify(decryptedSecretObject6.getSecretMessage1())) {
            System.out.println("lathos upografi");
            clientSocket.close();
        } else {
            System.out.println("swsti upografi");
             DHclient dh = new DHclient(clientSocket);

        dh.DHagreement(ois, oos, jsCert.getPublicKey(), hmap);
        clientSocket.close();
        }

       
    }

}
