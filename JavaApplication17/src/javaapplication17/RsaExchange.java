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
import java.util.HashMap;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author giorgos
 */
public class RsaExchange {
String path="C:\\Users\\giorgos\\Music\\JavaApplication17";
    public static String generateString() {
        String uuid = UUID.randomUUID().toString();
        return "uuid = " + uuid;
    }
    HashMap<String, String> hmap = new HashMap<String, String>();

    public void rsa() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, SignatureException, Exception {

        System.out.println("Receiver Started");
        Certificates cer = new Certificates();
        //cer.star();

        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream fs = new FileInputStream(path+"\\clientCert.jks");
        keystore.load(fs, "10212433".toCharArray());

        KeyStore keystore1 = KeyStore.getInstance("JKS");
        FileInputStream fs1 = new FileInputStream(path+"\\edw.jks");
        keystore1.load(fs1, "10212433".toCharArray());

        KeyGenerator keyGen;
//kataskeyi kleidiou 256bit
        keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
System.out.println("bit"+secretKey.getEncoded().length);
        Socket clientSocket = new Socket("127.0.0.1", 12347);

        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());

//SealedObject s = (SealedObject)ois.readObject();
        SecretObject decryptedSecretObject = (SecretObject) ois.readObject();

        if (hmap.containsKey(decryptedSecretObject.Uid())) {
        } else {
            hmap.put(decryptedSecretObject.Uid(), decryptedSecretObject.Uid());
        }

        //  PublicKey keyl = decryptedSecretObject.getSecretMessage();
        X509Certificate jsCert = decryptedSecretObject.getcert();
        //to chipher gia na kryptografw m e to dimosio kleidi
        //den me afine na xrisimopoihsw sealedobject dioti ebgaze exception gia ta bytes pou metefera
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, jsCert.getPublicKey());
        Aes aes = new Aes();
        System.out.println("edw eiani" + secretKey.getEncoded());

        //keystore.getCertificate("cert").verify(decryptedSecretObject.getSecretMessage());
//tsekarei an  einai o server meso tou public kleidiou tou to opoio exei upogegrafei to pistopoiitiko tou 
        System.out.println("edw einai " + cer.Trust((X509Certificate) keystore.getCertificate("cert"), keystore1.getCertificate("cert").getPublicKey()));
        //an einai true tote ua steilei ston server to sumetriko kleidi alliws an einai false tha kleisei to socket 
        if (!cer.Trust(jsCert, keystore1.getCertificate("cert").getPublicKey())) {
            clientSocket.close();
        } else {

            SecretObject secretObject1 = new SecretObjectImpl((X509Certificate) keystore.getCertificate("cert"), generateString());
            //System.out.println("einai " + key.equals(keystore.getCertificate("cert").getPublicKey()));

//SealedObject so = new SealedObject(secretObject, cipher);
            oos.writeObject(secretObject1);
            oos.flush();

            //====================================
            Certificates ca = new Certificates();
            //=========================================================
            Signature signatureProvider = null;

            signatureProvider = Signature.getInstance("SHA1WithRSA");
            //fortwnw ki topothetw to private key tis CA

//edw
            signatureProvider.initSign(ca.loadPrivateKey(path+"\\id_rsaclient"));

            // signatureProvider.initSign(ce.loadPrivateKey("C:\\Users\\giorgos\\Music\\JavaApplication17\\id_rsaclient"));
            byte[] signature = signatureProvider.sign();

            //=========================================================
            signatureProvider.update(jsCert.getPublicKey().getEncoded());
            //signatureProvider.update(pkServer.getEncoded());

            SecretObject secretObject5 = new SecretObjectImpl(signatureProvider.sign(), generateString());
            oos.writeObject(secretObject5);
            oos.flush();

            SecretObject decryptedSecretObject6 = (SecretObject) ois.readObject();
            if (hmap.isEmpty()) {
                hmap.put(decryptedSecretObject6.Uid(), decryptedSecretObject6.Uid());
            } else if (hmap.containsKey(decryptedSecretObject6.Uid())) {
                clientSocket.close();
            } else {
                hmap.put(decryptedSecretObject6.Uid(), decryptedSecretObject6.Uid());
            }
            Signature clientSign = Signature.getInstance("SHA1withRSA");
            clientSign.initVerify(jsCert.getPublicKey());
            clientSign.update(keystore.getCertificate("cert").getPublicKey().getEncoded());
            if (!clientSign.verify(decryptedSecretObject6.getSecretMessage1())) {
                System.out.println("lathos upografi");
                clientSocket.close();
            } else {
                System.out.println("swsti upografi");
            }

            //=============================
            //stelnw kryptografimena to secretkey
            //tha xrisimopoioysa sealed object alla den me afine logo megethous
            SecretObject secretObject = new SecretObjectImpl(cipher.doFinal(secretKey.getEncoded()), generateString());
            System.out.println(secretObject.Uid());
            System.out.println(generateString());
//SealedObject so = new SealedObject(secretObject, cipher);
            cipher.doFinal(secretKey.getEncoded());
            oos.writeObject(secretObject);

        }

//elexei an to sumentriko kleidi einai to idio to summetriko kleidi pou elave pisw apo ton server
//ggia dokimi 
        SecretObject decryptedSecretObject2 = (SecretObject) ois.readObject();

        if (hmap.containsValue(decryptedSecretObject2.Uid())) {
            clientSocket.close();
        } else {
            hmap.put(decryptedSecretObject2.Uid(), decryptedSecretObject2.Uid());
        }
        SecretKey key1 = new SecretKeySpec(decryptedSecretObject2.getSecretMessage1(), "AES");
        System.out.println("edw ta kleidia einai idia" + key1.equals(secretKey));
        ois.close();
        oos.close();
        System.out.println("End Receiver");
        clientSocket.close();
    }

}
