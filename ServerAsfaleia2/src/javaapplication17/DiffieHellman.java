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
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.UUID;
import static javaapplication17.RsaExchange.generateString;
import static javaapplication17.StS.generateString;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;

/**
 *
 * @author giorgos
 */
public class DiffieHellman {

    private Socket clientsocket;

    public static String generateString() {
        String uuid = UUID.randomUUID().toString();
        return "uuid = " + uuid;
    }

    String path = "C:\\Users\\giorgos\\Music\\ServerAsfaleia2";

    public void StartParty(HashMap<String, String> hmap, Socket socket) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException, SignatureException, Exception {
        clientsocket = socket;
        KeyStore keystore1 = KeyStore.getInstance("JKS");
        FileInputStream fs1 = new FileInputStream(path+"\\serverCert.jks");
        keystore1.load(fs1, "10212433".toCharArray());

        KeyStore keystore;

        keystore = KeyStore.getInstance("JKS");
        FileInputStream fs = new FileInputStream(path+"\\edw.jks");
        keystore.load(fs, "10212433".toCharArray());

        System.out.println("Server Started");
        CertsCa ca = new CertsCa();
        //ca.star();

        ObjectOutputStream oos = new ObjectOutputStream(clientsocket.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(clientsocket.getInputStream());

// stelnei to pistopoiitiko tou ston client ki etsi o client ki taytopoiei oti exei tin idia ca alla pairnei ki to public key tou
        SecretObject secretObject = new SecretObjectImpl((X509Certificate) keystore1.getCertificate("cert"), generateString());
        oos.writeObject(secretObject);
        oos.flush();
        //lambanei to pistopoiitiko tou client pou periexei to public key tou
        SecretObject decryptedSecretObject1 = (SecretObject) ois.readObject();
        X509Certificate jsCert = decryptedSecretObject1.getcert();
        //elenxei an exoun upogegrafei apo tin ca ki to kleidi antapokrinetai se ayton pou to esteile
        if (!ca.Trust(jsCert, keystore.getCertificate("cert").getPublicKey())) {
            clientsocket.close();
        }

        System.out.println("edw einai to public key tou client" + jsCert.getPublicKey());

        Signature signatureProvider = null;

        signatureProvider = Signature.getInstance("SHA1WithRSA");
        //fortwnw ki topothetw to private key tis CA

//edw
        signatureProvider.initSign(ca.loadPrivateKey(path+"\\id_rsaserver"));

        // signatureProvider.initSign(ce.loadPrivateKey("C:\\Users\\giorgos\\Music\\JavaApplication17\\id_rsaclient"));
        byte[] signature = signatureProvider.sign();

        //=========================================================
        signatureProvider.update(jsCert.getPublicKey().getEncoded());
        //signatureProvider.update(pkServer.getEncoded());

        SecretObject secretObject5 = new SecretObjectImpl(signatureProvider.sign(), generateString());
        oos.writeObject(secretObject5);
        oos.flush();

        //lamvanw tin upografi
        SecretObject decryptedSecretObject6 = (SecretObject) ois.readObject();
        Signature clientSign = Signature.getInstance("SHA1withRSA");
        clientSign.initVerify(jsCert.getPublicKey());
        clientSign.update(keystore1.getCertificate("cert").getPublicKey().getEncoded());
        if (!clientSign.verify(decryptedSecretObject6.getSecretMessage1())) {
            System.out.println("lathos upografi");
        } else {
            System.out.println("swsti upografi");
              DHserver dh = new DHserver(socket);

        dh.DHagreement(ois, oos, jsCert.getPublicKey(), hmap);
        clientsocket.close();
        }

      
    }
}
