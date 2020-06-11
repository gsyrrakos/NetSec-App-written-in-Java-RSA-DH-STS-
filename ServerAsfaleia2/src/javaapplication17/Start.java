/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author giorgos
 */
public class Start implements Runnable {

    private Socket clientsocket;
    private BufferedReader in;
    private int prot;
    private int clientNumber;
    HashMap<String, String> hmap;

    public Start(int number, HashMap<String, String> hma, int protocol) {

        clientNumber = number;
        hmap = hma;
        prot = protocol;
    }

    private void log(String s) {
        System.out.println(s);
    }
    ServerSocket welcomeSocket;
    Socket clientSocket;

    public void run() {
        try {
            log("[" + clientNumber + "]");

            if (prot == 1) {

                RsaExchange rsa = new RsaExchange();
                welcomeSocket = new ServerSocket(12347);
                clientSocket = welcomeSocket.accept();

                try {
                    System.out.println("Waiting for a connection...");

                    rsa.Rsa(hmap, clientSocket);

                    clientSocket.close();
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                }

            } else if (prot == 2) {

                DiffieHellman d = new DiffieHellman();
                System.out.println("Waiting for a connection...");
                welcomeSocket = new ServerSocket(12348);
                clientSocket = welcomeSocket.accept();
                try {

                    d.StartParty(hmap, clientSocket);
                    clientSocket.close();

                } catch (IOException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (CertificateException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeySpecException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                }

            } else if (prot == 3) {

                StS st = new StS();
                welcomeSocket = new ServerSocket(12349);
                clientSocket = welcomeSocket.accept();
                try {

                    st.StartParty(hmap, clientSocket);
                    clientSocket.close();
                } catch (IOException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (CertificateException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeySpecException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        } catch (IOException ex) {
            Logger.getLogger(Start.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
