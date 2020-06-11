/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.x500.X500Name;
import static org.bouncycastle.asn1.x500.style.RFC4519Style.name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 *
 * @author giorgos
 */
public class Certificates {

    PublicKey key;
 String path = "C:\\Users\\giorgos\\Music\\JavaApplication17";
    public PKCS10CertificationRequest Csr() throws NoSuchAlgorithmException, OperatorCreationException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        //ftiaxnw syndyasmo kleidiwn gia ton xrhsth
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair1 = gen.generateKeyPair();

        PrivateKey privateKey = pair1.getPrivate();
        PublicKey publicKey = pair1.getPublic();
        //-------------------------------------------
        key = publicKey;
        //=================================================
        ContentSigner signGen = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
        /*  
CN: CommonName
OU: OrganizationalUnit
O: Organization
L: Locality
S: StateOrProvinceName
C: CountryName
         */
        X500Principal subject = new X500Principal("C=GR, ST=KARLOVASI, L=" + "KARLOVASI" + "," + "O=" + "ICSD" + "," + "OU=" + "AEGEAN" + "," + "CN=" + name + "," + "Email=" + "");
//to builder gia to cert request ki orizw mesa thema ki public key tou cert tou xrhsth
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        PKCS10CertificationRequest request = builder.build(signGen);
writePemFile(privateKey, "RSA PRIVATE KEY", "id_rsaclient");
        return request;
    }
     private void writePemFile(Key key, String description, String filename)
            throws FileNotFoundException, IOException {
        PemFile(key, description);
        write(filename);

        System.out.println(String.format("%s successfully writen in file %s.", description, filename));
    }
    private PemObject pemObject;

    public void PemFile(Key key, String description) {
        this.pemObject = new PemObject(description, key.getEncoded());
    }

    public void write(String filename) throws FileNotFoundException, IOException {
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        try {
            pemWriter.writeObject(this.pemObject);
        } finally {
            pemWriter.close();
        }

    }
//gia na parw to priv key
    public  PrivateKey loadPrivateKey(String fileName)
            throws IOException, GeneralSecurityException {
        PrivateKey key = null;
        FileInputStream is = null;
        try {
            //is = fileName.getClass().getResourceAsStream(fileName);
            is = new FileInputStream(fileName);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ")
                            && line.endsWith(" PRIVATE KEY-----")) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }
            //
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePrivate(keySpec);
        } finally {
            closeSilent(is);
        }
        return key;
    }

    public static void closeSilent(final InputStream is) {
        if (is == null) {
            return;
        }
        try {
            is.close();
        } catch (Exception ign) {
        }

    }
//methodos na apothikeysw to cert toy clinet
    public void star() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, java.security.cert.CertificateException, OperatorCreationException, GeneralSecurityException, NoSuchProviderException, SignatureException, javax.security.cert.CertificateException, Exception {

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream fs = new FileInputStream(path+"\\edw.jks");
        keystore.load(fs, "10212433".toCharArray());
        KeyStore ks = KeyStore.getInstance("JKS");
        //eggrafi tou certificate sto keystore
        FileOutputStream fis = new FileOutputStream("clientCert.jks");
        ks.load(null, "10212433".toCharArray());
        ks.setCertificateEntry("cert", Upografi(path+"\\edw.jks", "gi", Csr(), loadPrivateKey("C:\\Users\\giorgos\\Music\\ServerAsfaleia2\\id_rsa"), key, (X509Certificate) keystore.getCertificate("cert"), "")
        );
        ks.store(fis, "10212433".toCharArray());
        fis.close();
    }

    public static X509Certificate Upografi(String path, String name, PKCS10CertificationRequest inputCSR, PrivateKey caPrivate,
            PublicKey ky, X509Certificate cr, String email)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException,
            OperatorCreationException, javax.security.cert.CertificateException, java.security.cert.CertificateException, Exception {
//o algorithmos ppou tha einai ta kleidia mas
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgId);

        AsymmetricKeyParameter kleidia = PrivateKeyFactory.createKey(caPrivate
                .getEncoded());
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(ky.getEncoded());
//byte[] certReqInfo=;

        PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(inputCSR.getEncoded());

        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                new X500Name(cr.getIssuerDN().getName()),
                new BigInteger(BigInteger.valueOf(System.currentTimeMillis()).toString()),
                new Date("05/12/17"),
                new Date("11/12/2017"),
                pk10Holder.getSubject(),
                keyInfo);
        myCertificateGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(cr));
//myCertificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(ky));
        myCertificateGenerator.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
                new GeneralName(GeneralName.rfc822Name, email)));
//dimiourgw tin ypografi i opoia exei ginei me to private key tis CA ki ton algorithmos SHA1withRsa
        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                .build(kleidia);
//dimiourgw ena holder gia na kratisw to cert pou tha dimiourghthei
        X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
//pairnw se morfi aplou certificate to cert apo to holder metatrepontas to se ans1 morfi
        Certificate eeX509CertificateStructure = holder.toASN1Structure();

//dimiourgw ena dimiourgo cert me idiotitew x509 tis bouncy castle
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        // Read Certificate diavazw to certificate
        InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
        //dimiourgw to teliko certificate
        X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);

        is1.close();
//apothkeyw to cert sto filder tou xrhsth
        //  saveCertificate(path, theCert, name);
        //ola ta parakatw eginan gia logous dokimis
        System.out.println("ti leei" + theCert.getIssuerDN());
        System.out.println("ti leei" + theCert);
        // checkServerTrusted(getcert(name), cr.getPublicKey(), "");
        System.out.println(theCert.getSubjectAlternativeNames());
        return theCert;
        //return null;
    }
//methodos elexou
    public boolean Trust(X509Certificate cert, PublicKey key) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException, Exception {
        boolean trust = true;
        KeyStore keystore1 = KeyStore.getInstance("JKS");
        FileInputStream fs1 = new FileInputStream(path+"\\edw.jks");
        keystore1.load(fs1, "10212433".toCharArray());
        if (cert == null) {
            trust = false;
            throw new IllegalArgumentException("null or zero-length certificate chain");
            //res=true;
        }

        if (!cert.equals(keystore1.getCertificate("cert"))) {
            //Not your CA's. Check if it has been signed by your CA
            cert.verify(key);
            //keystore1.getCertificate("cert").verify(key);
            trust = true;

        } else {
            trust = false;
            throw new Exception("Certificate not trusted");
        }
        //If we end here certificate is trusted. Check if it has expired.  
        try {
            cert.checkValidity(new Date("05/12/2017"));
            trust = true;
        } catch (Exception e) {
            trust = false;
            throw new Exception("Certificate not trusted. It has expired", e);
        }
        return trust;
    }
}
