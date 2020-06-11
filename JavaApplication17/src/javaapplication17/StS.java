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
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.UUID;

/**
 *
 * @author giorgos
 */
public class StS {

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
        Socket clientSocket = new Socket("127.0.0.1", 12349);
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

        //System.out.println("Server - Packet Data is: '" + decryptedSecretObject.getSecretMessage()+ "'");
        //  PublicKey keyl = decryptedSecretObject.getSecretMessage();
        X509Certificate jsCert = decryptedSecretObject.getcert();
        //elenxei an exoun upogegrafei apo tin ca
        if (!cer.Trust(jsCert, keystore1.getCertificate("cert").getPublicKey())) {
            clientSocket.close();
        }
        System.out.println("edw einai to public key tou server" + jsCert.getPublicKey());
        SecretObject secretObject = new SecretObjectImpl((X509Certificate) keystore.getCertificate("cert"), generateString());
        oos.writeObject(secretObject);
        oos.flush();
        DHclient dh = new DHclient(clientSocket);
        dh.DHSTs(ois, oos, jsCert.getPublicKey(), hmap);
//dh.DHagreement(ois, oos, jsCert.getPublicKey(), hmap);
    }

}
