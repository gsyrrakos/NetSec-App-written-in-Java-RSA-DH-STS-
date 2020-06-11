/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

/**
 *
 * @author giorgos
 */
public class GUI implements ActionListener {

    JPanel pl1;
    JRadioButton five;
    JRadioButton eight;
    JRadioButton nine;
    JButton button;

    GUI() {

        ButtonGroup group = new ButtonGroup();
        JFrame frame = new JFrame("Modify");//Dilwseis twn frames 

        five = new JRadioButton("RSA", true);//diiourgoume ts koukides
        eight = new JRadioButton("DH");
        nine = new JRadioButton("Sts");
        pl1 = new JPanel();
        five.addActionListener(this);//orizoume to ti tha kanei ayto to koumpi mesw tou listener 
//stin ousia me ayto mporoume na prosthesdoume leitouyrgies sto koumpi mas
        eight.addActionListener(this);
        button = new JButton("OK");
        button.addActionListener(this);
        group.add(five);
        group.add(eight);
        group.add(nine);

        pl1.add(five);
        pl1.add(eight);
        pl1.add(nine);
        pl1.add(button);
        frame.add(pl1);

        frame.setSize(400, 400);//Diastaseis
        frame.setVisible(true);//Visible

        frame.setResizable(false);//Den mporei na allaksei to megethos tou parathurou
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocationRelativeTo(null);//Gia na einai sto kentro

    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == button) {

            //1o erwtima
            if (five.isSelected()) {
                Socket clientSocket;
                try {
                    clientSocket = new Socket("127.0.0.1", 15059);
                    DataOutputStream oos = new DataOutputStream(clientSocket.getOutputStream());
                    oos.writeInt(1);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                }

                RsaExchange rs = new RsaExchange();
                try {
                    rs.rsa();
                   // System.exit(0);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (CertificateException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeySpecException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                }

            }

            //2o erwtima
            if (eight.isSelected()) {
                Socket clientSocket;
                try {
                    clientSocket = new Socket("127.0.0.1", 15059);
                    DataOutputStream oos = new DataOutputStream(clientSocket.getOutputStream());
                    oos.writeInt(2);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                }

                HashMap<String, String> hmap = new HashMap<String, String>();
                DiffieHellman d = new DiffieHellman();
                try {
                    d.startParty(hmap);
                   // System.exit(0);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (CertificateException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                }

            }

            //3o erwtima
            if (nine.isSelected()) {
                Socket clientSocket;
                try {
                    clientSocket = new Socket("127.0.0.1", 15059);
                    DataOutputStream oos = new DataOutputStream(clientSocket.getOutputStream());
                    oos.writeInt(3);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                }

                HashMap<String, String> hmap = new HashMap<String, String>();
                StS st = new StS();
                try {
                    st.startParty(hmap);
                   // System.exit(0);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (CertificateException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                }

            }

        }

    }
}
