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
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.UUID;
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
public class StS {

    private Socket clientsocket;

    public static String generateString() {
        String uuid = UUID.randomUUID().toString();
        return "uuid = " + uuid;
    }
    String path = "C:\\Users\\giorgos\\Music\\ServerAsfaleia2";

    public void StartParty(HashMap<String, String> hmap, Socket socket) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException, SignatureException, Exception {
        clientsocket = socket;
        KeyStore keystore1 = KeyStore.getInstance("JKS");
        FileInputStream fs1 = new FileInputStream(path + "\\serverCert.jks");
        keystore1.load(fs1, "10212433".toCharArray());

        KeyStore keystore;

        keystore = KeyStore.getInstance("JKS");
        FileInputStream fs = new FileInputStream(path + "\\edw.jks");
        keystore.load(fs, "10212433".toCharArray());

        System.out.println("Server Started");
        CertsCa ca = new CertsCa();
        //ca.star();
        // Create key

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
        //elegxei ki gia replay
        if (hmap.isEmpty()) {
            hmap.put(decryptedSecretObject1.Uid(), decryptedSecretObject1.Uid());
        } else if (hmap.containsKey(decryptedSecretObject1.Uid())) {
            clientsocket.close();
        } else {
            hmap.put(decryptedSecretObject1.Uid(), decryptedSecretObject1.Uid());
        }

        if (!ca.Trust(jsCert, keystore.getCertificate("cert").getPublicKey())) {
            clientsocket.close();
        }

        System.out.println("edw einai to public key tou client" + jsCert.getPublicKey());
        DHserver dh = new DHserver(socket);
        dh.DHSTs(ois, oos, jsCert.getPublicKey(), hmap);

    }
}
