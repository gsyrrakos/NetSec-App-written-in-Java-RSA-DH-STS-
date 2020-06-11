/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
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

/**
 *
 * @author giorgos
 */
public class DHclient {
//pano apo 2048 bit petaei exception
//2048 java.security.InvalidAlgorithmParameterException: DH key size must be multiple of 64, and can only range from 512 to 2048 (inclusive). The specific key size 3072 is not supported
    //bits//gia na antimetopisei ta longjam

    private SecretKey sharedKey;
    private SecureRandom random;
    public byte[] iv;//to theloume gia tin mellontiki kryptografhsh me AES cbc
    Socket so;

    public DHclient(Socket soc) {
this.random = new SecureRandom();
        so = soc;
        fixKeyLength();
    }

    public static String generateString() {
        String uuid = UUID.randomUUID().toString();
        return "uuid = " + uuid;
    }
    String path = "C:\\Users\\giorgos\\Music\\JavaApplication17";
    final protected static char[] hexArray = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public void DHSTs(ObjectInputStream ois, ObjectOutputStream oos, PublicKey key, HashMap<String, String> hmap) throws GeneralSecurityException, ClassNotFoundException {
        try {

            //an orisoume os provider to BC dexetai ki prime panw apo 2048 
//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
          //  KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH","BC");
           // KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman","BC");
           //  KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman","BC");
           
           KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");

            // receive gen,prime,public iv apo ton  Server
            SecretObject decryptedSecretObject = (SecretObject) ois.readObject();

            BigInteger generator = decryptedSecretObject.getgen();

            BigInteger primeModules = decryptedSecretObject.getmod();

            PublicKey publicKey = decryptedSecretObject.getSecretMessage();

            this.iv = decryptedSecretObject.getiv();

            //elexos gia replay
            if (hmap.containsKey(decryptedSecretObject.Uid())) {
                so.close();
            } else {
                hmap.put(decryptedSecretObject.Uid(), decryptedSecretObject.Uid());
            }
this.random.nextBytes(this.iv);
            DHParameterSpec dhPS = new DHParameterSpec(primeModules, generator);
            keyPairGen.initialize(dhPS, this.random);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            PublicKey pkServer = publicKey;

            // stelnw to publicKey stto Client
            SecretObject secretObject = new SecretObjectImpl(keyPair.getPublic(), generateString());
            oos.writeObject(secretObject);
            oos.flush();
            // System.out.println(" Pub: " + bytesToHex(keyPair.getPublic().getEncoded()));
            System.out.println("edwto" + keyPair.getPublic());

            //out.flush();
            // vrikssw to sharedKey
            keyAgree.init(keyPair.getPrivate());
            keyAgree.doPhase(pkServer, true);
            this.sharedKey = keyAgree.generateSecret("AES");
            System.out.println(sharedKey.getEncoded());
            //**************************//

            // read keyPair Sign
            Certificates ce = new Certificates();

            //=======================================================
            boolean useBouncyCastleProvider = false;

            Provider provider = null;
            if (useBouncyCastleProvider) {
                provider = new BouncyCastleProvider();
                Security.addProvider(provider);
            }

            //DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
            //AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find(hashingAlgorithm);
            // DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hash);
            // byte[] hashToEncrypt = hash+plainText.getBytes();
            // Signature
            Signature signatureProvider = null;

            signatureProvider = Signature.getInstance("SHA1WithRSA");
            //fortwnw ki topothetw to private key tis CA

//edw
            signatureProvider.initSign(ce.loadPrivateKey(path + "\\id_rsaclient"));

            // signatureProvider.initSign(ce.loadPrivateKey("C:\\Users\\giorgos\\Music\\JavaApplication17\\id_rsaclient"));
            byte[] signature = signatureProvider.sign();

            //=========================================================
            signatureProvider.update(keyPair.getPublic().getEncoded());
            signatureProvider.update(pkServer.getEncoded());

            //==============================
            SecretObject secretObject1 = new SecretObjectImpl(signatureProvider.sign(), generateString());
            oos.writeObject(secretObject1);
            oos.flush();

            // pairnwtin ypografytou  Server 
            SecretObject decryptedSecretObject3 = (SecretObject) ois.readObject();
//decryptedSecretObject3.getSign();
            if (hmap.containsKey(decryptedSecretObject3.Uid())) {
                so.close();
            } else {
                hmap.put(decryptedSecretObject3.Uid(), decryptedSecretObject3.Uid());
            }
            // verify the signature
            Signature serverSign = Signature.getInstance("SHA1withRSA");
            serverSign.initVerify(key);
            serverSign.update(pkServer.getEncoded());
            serverSign.update(keyPair.getPublic().getEncoded());
//System.out.println(serverSign.verify(Base64.getDecoder().decode(decryptedSecretObject3.getSign().sign())));
            if (!serverSign.verify(decryptedSecretObject3.getSecretMessage1())) {
                System.out.println("lathos upografi" + decryptedSecretObject3.getSecretMessage1());
                so.close();
            } else {
                System.out.println("swsti upografi");
                
                     //gia logous dokimis !!!!!
        SecretObject secretObject5 = new SecretObjectImpl(sharedKey.getEncoded(), generateString());
        oos.writeObject(secretObject5);
        oos.flush();
           
        //fernw to kleidi se 256 bit 
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash;
            hash = digest.digest(sharedKey.getEncoded());
             hash = Arrays.copyOf(hash, 32);
                SecretKey key2 = new SecretKeySpec(hash, "AES");
//methodoi kryptografisis ki apokrypto
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

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
        KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman");
        KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");

        // receive generator, prime, publickai iv apo ton  Server
        SecretObject decryptedSecretObject = (SecretObject) ois.readObject();

        BigInteger generator = decryptedSecretObject.getgen();

        BigInteger primeModules = decryptedSecretObject.getmod();

        PublicKey publicKey = decryptedSecretObject.getSecretMessage();
        //to xreiazomaste gia mellontiki xrhsh AES cbc
        this.iv = decryptedSecretObject.getiv();

        //elexos gia replay
        if (hmap.containsKey(decryptedSecretObject.Uid())) {
            so.close();
        } else {
            hmap.put(decryptedSecretObject.Uid(), decryptedSecretObject.Uid());
        }

        DHParameterSpec dhPS = new DHParameterSpec(primeModules, generator);
        keyPairGen.initialize(dhPS, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();

        PublicKey pkServer = publicKey;

        // stelnw to publicKey sto Client
        SecretObject secretObject = new SecretObjectImpl(keyPair.getPublic(), generateString());
        oos.writeObject(secretObject);
        oos.flush();
        System.out.println("edwto" + keyPair.getPublic());

        //out.flush();
        // upologizw to sharedKey
        keyAgree.init(keyPair.getPrivate());
        keyAgree.doPhase(pkServer, true);
        this.sharedKey = keyAgree.generateSecret("AES");
        System.out.println(sharedKey);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash;
            hash = digest.digest(sharedKey.getEncoded());
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
        //**************************//
//gia logous dokimis !!!!!
        SecretObject secretObject5 = new SecretObjectImpl(sharedKey.getEncoded(), generateString());
        oos.writeObject(secretObject5);
        oos.flush();

    }

    public void st() throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException {
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


//kwdikas gia na diorthwnei to eror pou yphrxe me to jdk gia to 
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
    if (newMaxKeyLength < 256)
        throw new RuntimeException(errorString); // hack failed
}


}
