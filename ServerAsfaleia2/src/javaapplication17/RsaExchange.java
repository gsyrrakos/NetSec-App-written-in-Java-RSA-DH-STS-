/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author giorgos
 */
public class RsaExchange {

    public static String generateString() {
        String uuid = UUID.randomUUID().toString();
        return "uuid = " + uuid;
    }
    String path = "C:\\Users\\giorgos\\Music\\ServerAsfaleia2";

    public void Rsa(HashMap<String, String> hmap, Socket clientsocket) throws ClassNotFoundException, IOException {

        try {

            KeyStore keystore;
//keystore gia tin ca
            keystore = KeyStore.getInstance("JKS");
            FileInputStream fs = new FileInputStream(path + "\\edw.jks");
            keystore.load(fs, "10212433".toCharArray());

            KeyStore keystore1 = KeyStore.getInstance("JKS");
            FileInputStream fs1 = new FileInputStream(path + "\\serverCert.jks");
            keystore1.load(fs1, "10212433".toCharArray());

            System.out.println("Server Started");
            CertsCa ca = new CertsCa();
            //ca.star();

            ObjectOutputStream oos = new ObjectOutputStream(clientsocket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(clientsocket.getInputStream());

            //p[airnei to public key tou cert tou server ki to stelnei ston client me to opoio tha kanei to verify to pistopoiitiko tou .an den bgalei sfalma tote einai komple diot exon upogegrafei
            //apo tin idia CA
            PublicKey key = keystore1.getCertificate("cert").getPublicKey();

            // stelnei to pistopoiitiko tou ston client ki etsi o client ki taytopoiei oti exei tin idia ca alla pairnei ki to public key tou
            SecretObject secretObject = new SecretObjectImpl((X509Certificate) keystore1.getCertificate("cert"), generateString());
            //System.out.println("einai " + key.equals(keystore.getCertificate("cert").getPublicKey()));
            //SealedObject so = new SealedObject(secretObject, cipher);

            oos.writeObject(secretObject);

            System.out.println("Sent Sealed Object"
                    + " " + key);
//apokryptografia me to private jey tou
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, ca.loadPrivateKey(path + "\\id_rsaserver"));

            //SealedObject s = (SealedObject) ois.readObject();
            SecretObject decryptedSecretObject3 = (SecretObject) ois.readObject();// (SecretObject) s.getObject(dcipher);

            if (hmap.isEmpty()) {
                hmap.put(decryptedSecretObject3.Uid(), decryptedSecretObject3.Uid());
            } else if (hmap.containsKey(decryptedSecretObject3.Uid())) {
                clientsocket.close();
            } else {
                hmap.put(decryptedSecretObject3.Uid(), decryptedSecretObject3.Uid());
            }
//edw pairnw to pistopoiitiko tou client ara ki public key toy
            X509Certificate jsCert = decryptedSecretObject3.getcert();
            System.out.println(jsCert.getPublicKey());

            Signature signatureProvider = null;

            signatureProvider = Signature.getInstance("SHA1WithRSA");
            //fortwnw ki topothetw to private key tis CA

//edw
            signatureProvider.initSign(ca.loadPrivateKey(path + "\\id_rsaserver"));

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
            if (hmap.isEmpty()) {
                hmap.put(decryptedSecretObject6.Uid(), decryptedSecretObject6.Uid());
            } else if (hmap.containsKey(decryptedSecretObject6.Uid())) {
                clientsocket.close();
            } else {
                hmap.put(decryptedSecretObject6.Uid(), decryptedSecretObject6.Uid());
            }
            Signature clientSign = Signature.getInstance("SHA1withRSA");
            clientSign.initVerify(jsCert.getPublicKey());
            clientSign.update(keystore1.getCertificate("cert").getPublicKey().getEncoded());
            if (!clientSign.verify(decryptedSecretObject6.getSecretMessage1())) {
                System.out.println("lathos upografi");
            } else {
                System.out.println("swsti upografi");
            }

            SecretObject decryptedSecretObject4 = (SecretObject) ois.readObject();
           //elegxos relay
            if (hmap.isEmpty()) {
                hmap.put(decryptedSecretObject4.Uid(), decryptedSecretObject4.Uid());
            } else if (hmap.containsKey(decryptedSecretObject4.Uid())) {
                clientsocket.close();
            } else {
                hmap.put(decryptedSecretObject4.Uid(), decryptedSecretObject4.Uid());
            }
            // SecretObject decryptedSecretObject3 = (SecretObject) ois.readObject();
            Aes aes = new Aes();
//apokryptografisi
            SecretKey key1 = new SecretKeySpec(dcipher.doFinal(decryptedSecretObject4.getSecretMessage1()), "AES");

            //to symetriko kleidi gia to AES 256bit
            System.out.println("Server - Packet Data is: '" + key1 + "'");

            //System.out.println("edw einai " + ca.Trust((X509Certificate) keystore1.getCertificate("cert"), keystore.getCertificate("cert").getPublicKey()));
            //SecretObject secretObject2 = new SecretObjectImpl(aes.decrypt(decryptedSecretObject.getSecretMessage1(), ca.loadPrivateKey("C:\\Users\\subze\\Documents\\NetBeansProjects\\ServerAsfaleia2\\id_rsa")).getEncoded()
            //	);
            oos.flush();

            SecretObject sec2 = new SecretObjectImpl(key1.getEncoded(), generateString());
            oos.writeObject(sec2);

            oos.close();

            ois.close();
            clientsocket.close();
        } catch (IOException ex) {
            Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
