/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication17;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

/**
 *
 * @author giorgos
 */
public class Server {

    public static void main(String[] args) throws Exception {
        //h());
        int x;

        ServerSocket Socket = new ServerSocket(15059);
          while (true) {
        Socket tSocket = Socket.accept();
        DataOutputStream oos = new DataOutputStream(tSocket.getOutputStream());
        DataInputStream ois = new DataInputStream(tSocket.getInputStream());
        x = ois.readInt();

        HashMap<String, String> hmap = new HashMap<String, String>();
            int clientCount = 0;
            int port = 1234;

           
                //SSLSocket sChannel = (SSLSocket) server.accept();
                //sChannel.setWantClientAuth(true);
             new Thread(new Start( ++clientCount, hmap, x)).start();
        
        
        
        
        
        
        
        
          }

            

                

           

        

        

    }
}
