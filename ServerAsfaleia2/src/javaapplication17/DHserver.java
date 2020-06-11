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
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;
import sun.nio.cs.StandardCharsets;

/**
 *
 * @author giorgos
 */
public class DHserver {

    private static final int ivmhkos = 16; //bits
    String path = "C:\\Users\\giorgos\\Music\\ServerAsfaleia2";
    String path2 = "C:\\Users\\giorgos\\Music\\JavaApplication17";
    private SecretKey sharedKey;
    private SecureRandom random;
    public byte[] iv;//to theloume gia tin mellontiki kryptografhsh me AES cbc
    Socket so;

    public DHserver(Socket soc) {
        this.random = new SecureRandom();
        this.iv = new byte[ivmhkos];
        so = soc;
        fixKeyLength();
    }

    private BigInteger generateBigPrime(int bits) {
        return BigInteger.probablePrime(bits, random);
    }

    public static String generateString() {
        String uuid = UUID.randomUUID().toString();
        return "uuid = " + uuid;
    }

    public void DHSTs(ObjectInputStream ois, ObjectOutputStream oos, PublicKey key, HashMap<String, String> hmap) throws GeneralSecurityException, ClassNotFoundException {
        try {
            //an orisoume os provider to BC dexetai ki prime panw apo 2048 
//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            // KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH","BC");
            //KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman","BC");
            // KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman","BC");

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            KeyAgreement keyagree = KeyAgreement.getInstance("DiffieHellman");
            KeyFactory factorkey = KeyFactory.getInstance("DiffieHellman");

            BigInteger P = this.generateBigPrime(2048);
            BigInteger gen = this.generateBigPrime(2048);
            this.random.nextBytes(this.iv);
//orizoume ta parameters tou DH gia na ftiaxoume to kleidi
            DHParameterSpec dhPS = new DHParameterSpec(P, gen);
            keyPairGen.initialize(dhPS, this.random);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // stelnoume ta parameters ston Client
            SecretObject secretObject = new SecretObjectImpl(keyPair.getPublic(), P, gen, iv, generateString());
            oos.writeObject(secretObject);
            oos.flush();

            //pairnoume to publicKey apo Client
            SecretObject decryptedSecretObject = (SecretObject) ois.readObject();
           
            //vheck gia replay 
            if (hmap.containsKey(decryptedSecretObject.Uid())) {
                System.out.println("eroor");
                so.close();
            } else {
                hmap.put(decryptedSecretObject.Uid(), decryptedSecretObject.Uid());
            }
            System.out.println(decryptedSecretObject.Uid());

            PublicKey pkClient = decryptedSecretObject.getSecretMessage();
            
            System.out.println("edwto" + pkClient);
            //vriskoume to sharedKey
            keyagree.init(keyPair.getPrivate());
            keyagree.doPhase(pkClient, true);

            this.sharedKey = keyagree.generateSecret("AES");
            System.out.println(sharedKey.getEncoded());
//=====================================
//ftiaxnw hash tou kleidiou gia na to ferw se morfi 256 bit
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash;
            hash = digest.digest(sharedKey.getEncoded());
// upografi
            //================================
            CertsCa ca = new CertsCa();
            Signature signatureProvider = null;
            signatureProvider = Signature.getInstance("SHA1WithRSA");
            //fortwnw ki topothetw to private key tis CA
            signatureProvider.initSign(ca.loadPrivateKey(path + "\\id_rsaserver"));
//edw

            byte[] signature = signatureProvider.sign();

            //===============================
            Signature sign = Signature.getInstance("SHA1withRSA");
            sign.initSign(ca.loadPrivateKey(path + "\\id_rsaserver"));
            factorkey = KeyFactory.getInstance("RSA");
//pairnw to public key tou xristi
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream fs = new FileInputStream(path2 + "\\clientCert.jks");
            keystore.load(fs, "10212433".toCharArray());

//stelnw to  publicKeySign ston client
            SecretObject decryptedSecretObject3 = (SecretObject) ois.readObject();
            if (hmap.containsKey(decryptedSecretObject3.Uid())) {
                so.close();
            } else {
                hmap.put(decryptedSecretObject3.Uid(), decryptedSecretObject3.Uid());
            }

            System.out.println(decryptedSecretObject3.getSecretMessage1());

            signatureProvider.update(keyPair.getPublic().getEncoded());
            signatureProvider.update(pkClient.getEncoded());
            // send signature to Client
            SecretObject secretObject1 = new SecretObjectImpl(signatureProvider.sign(), generateString());
            oos.writeObject(secretObject1);
            oos.flush();

            // verify the signature
            Signature clientSign = Signature.getInstance("SHA1withRSA");
            clientSign.initVerify(key);
            clientSign.update(pkClient.getEncoded());
            clientSign.update(keyPair.getPublic().getEncoded());
           
            if (!clientSign.verify(decryptedSecretObject3.getSecretMessage1())) {
                System.out.println("lathos upografi");
            } else {
                System.out.println("swsti upografi");

                //gia logous dokimis na deixw oti eftaixa to idio key
                SecretObject decryptedSecretObject5 = (SecretObject) ois.readObject();
                SecretKey key1 = new SecretKeySpec(decryptedSecretObject5.getSecretMessage1(), "AES");

                System.out.println(sharedKey.equals(key1));
//pairnw mono ta 256 bit pou thelw
                hash = Arrays.copyOf(hash, 32);
                SecretKey key2 = new SecretKeySpec(hash, "AES");

                Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, key2, new IvParameterSpec(iv));
                byte[] encValue = cipher.doFinal("ti leei".getBytes());

                System.out.println("edw to krypt" + new String(encValue));
//apokryptografw
                Cipher dcipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
                dcipher.init(Cipher.DECRYPT_MODE, key2, new IvParameterSpec(iv));

                byte[] plainText = dcipher.doFinal(encValue);
                String dValue = new String(plainText);
                System.out.println("edw to apokrypt" + dValue);
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();

        }
    }

    public void DHagreement(ObjectInputStream ois, ObjectOutputStream oos, PublicKey key, HashMap<String, String> hmap) throws GeneralSecurityException, ClassNotFoundException, IOException {

        //to idiio apo panw apla den exei upografes
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
        KeyAgreement keyagree = KeyAgreement.getInstance("DiffieHellman");
        KeyFactory factorkey = KeyFactory.getInstance("DiffieHellman");

        BigInteger primeModules = this.generateBigPrime(2048);
        BigInteger gen = this.generateBigPrime(2048);
        this.random.nextBytes(this.iv);
//upologizouyme to kleidi vasi twn parameters
        DHParameterSpec dhPS = new DHParameterSpec(primeModules, gen);
        keyPairGen.initialize(dhPS, this.random);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // stelnoume generator primeModules publicKey iv sto Client
        SecretObject secretObject = new SecretObjectImpl(keyPair.getPublic(), primeModules, gen, iv, generateString());
        oos.writeObject(secretObject);
        oos.flush();

        //dexomaste to publicKey apo ton Client
        SecretObject decryptedSecretObject = (SecretObject) ois.readObject();
        if (hmap.containsKey(decryptedSecretObject.Uid())) {
            System.out.println("eroor");
            so.close();
        } else {
            hmap.put(decryptedSecretObject.Uid(), decryptedSecretObject.Uid());
        }
        System.out.println(decryptedSecretObject.Uid());
        
        PublicKey pkClient = decryptedSecretObject.getSecretMessage();
        
        System.out.println("edwto" + pkClient);
        //upologismos tou sharedKey
        keyagree.init(keyPair.getPrivate());
        keyagree.doPhase(pkClient, true);
        this.sharedKey = keyagree.generateSecret("AES");
        System.out.println(sharedKey.getFormat());
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash;
            hash = digest.digest(sharedKey.getEncoded());
        //gia logous dokimis na deixw oti eftaixa to idio key
        SecretObject decryptedSecretObject5 = (SecretObject) ois.readObject();
        SecretKey key1 = new SecretKeySpec(decryptedSecretObject5.getSecretMessage1(), "AES");

        System.out.println(sharedKey.equals(key1));
         hash = Arrays.copyOf(hash, 32);
                SecretKey key2 = new SecretKeySpec(hash, "AES");

                Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, key2, new IvParameterSpec(iv));
                byte[] encValue = cipher.doFinal("ti leei".getBytes());

                System.out.println("edw to krypt" + new String(encValue));
//apokryptografw
                Cipher dcipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
                dcipher.init(Cipher.DECRYPT_MODE, key2, new IvParameterSpec(iv));

                byte[] plainText = dcipher.doFinal(encValue);
                String dValue = new String(plainText);
                System.out.println("edw to apokrypt" + dValue);

    }

    public void st(PrivateKey aPrivate, PublicKey aPublic) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator
                .getInstance("DH");
        paramGen.init(1024);

// Generate the parameters
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = (DHParameterSpec) params
                .getParameterSpec(DHParameterSpec.class);

        keyGen.initialize(dhSpec);

        KeyPair alice_key = keyGen.generateKeyPair();
        KeyPair bob_key = keyGen.generateKeyPair();

        SecretKey secret_alice = combine(alice_key.getPrivate(),
                bob_key.getPublic());

        SecretKey secret_bob = combine(bob_key.getPrivate(),
                alice_key.getPublic());

        System.out.println(Arrays.toString(secret_alice.getEncoded()));
        System.out.println(Arrays.toString(secret_bob.getEncoded()));
    }

    SecretKey combine(PrivateKey aPrivate, PublicKey aPublic) throws InvalidKeyException, NoSuchAlgorithmException {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(aPrivate);
        ka.doPhase(aPublic, true);
        SecretKey secretKey = ka.generateSecret("AES");
        return secretKey;
    }
//methodos gia na ftiaxnei to bug tou jdk gia ta kleidia
    public static void fixKeyLength() {
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance();
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissions = con.newInstance();
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256) {
            throw new RuntimeException(errorString); // hack failed
        }
    }

}
