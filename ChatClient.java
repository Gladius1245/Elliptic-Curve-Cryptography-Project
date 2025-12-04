package com.example;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import java.util.Base64;

public class ChatClient {
    private final KeyPair keyPair;
    private SecretKey aesKey;

    public ChatClient() throws Exception {
        this.keyPair = CryptoUtils.generateKeyPair();
    }

    public void connect(String host, int port) throws Exception {
        System.out.println("Connecting to " + host + ":" + port + "...");

        try (Socket socket = new Socket(host, port);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            String serverPubKeyStr = in.readLine();
            PublicKey serverPubKey = CryptoUtils.stringToPublicKey(serverPubKeyStr);

            out.println(CryptoUtils.publicKeyToString(keyPair.getPublic()));

            byte[] sharedSecret = CryptoUtils.performECDH(keyPair.getPrivate(), serverPubKey);
            aesKey = CryptoUtils.deriveAESKey(sharedSecret);

            System.out.println("Secure channel established! Start typing (type 'exit' to quit):");

            new Thread(() -> {
                try {
                    String encryptedMsg;
                    while ((encryptedMsg = in.readLine()) != null) {
                        byte[] data = Base64.getDecoder().decode(encryptedMsg);
                        String msg = CryptoUtils.decrypt(data, aesKey);
                        System.out.println("Server: " + msg);
                    }
                } catch (Exception e) {
                    System.out.println("Connection closed.");
                }
            }).start();

            try (BufferedReader console = new BufferedReader(new InputStreamReader(System.in))) {
                String input;
                while ((input = console.readLine()) != null) {
                    if ("exit".equalsIgnoreCase(input)) break;
                    byte[] encrypted = CryptoUtils.encrypt(input, aesKey);
                    out.println(Base64.getEncoder().encodeToString(encrypted));
                }
            }
        }
    }

    // ADD THIS MAIN METHOD — THIS IS WHAT YOU WANTED!
    public static void main(String[] args) throws Exception {
        System.out.println("Starting ECC Chat Client...");
        new ChatClient().connect("localhost", 5000);
    }
}