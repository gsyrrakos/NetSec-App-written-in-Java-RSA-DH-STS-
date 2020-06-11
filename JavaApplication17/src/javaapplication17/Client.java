/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.PrivateKey;
import java.util.HashMap;

public class Client implements ActionListener {

    static PrivateKey keyp;

    public static void main(String[] args) throws Exception {

        String server = "localhost";

        if (args.length == 1) {
            server = args[0];
        }
        GUI g = new GUI();

        HashMap<String, String> hmap = new HashMap<String, String>();
        //3o erwtima
        StS st = new StS();
        // st.startParty(hmap);

//1o erwtima 
        RsaExchange rs = new RsaExchange();
        //  rs.rsa();
        //2o erwtima
        DiffieHellman d = new DiffieHellman();
//d.startParty(hmap);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
