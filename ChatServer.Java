package com.example;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import java.util.Base64;

public class ChatServer {
    private final KeyPair keyPair;
    private SecretKey aesKey;

    public ChatServer() throws Exception {
        this.keyPair = CryptoUtils.generateKeyPair();
    }

    public void start(int port) throws Exception {
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server listening on port " + port + "... Waiting for client...");

        try (Socket clientSocket = serverSocket.accept();
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {

            System.out.println("Client connected! Exchanging keys...");

            // Send server public key
            out.println(CryptoUtils.publicKeyToString(keyPair.getPublic()));

            // Receive client public key
            String clientPubKeyStr = in.readLine();
            PublicKey clientPubKey = CryptoUtils.stringToPublicKey(clientPubKeyStr);

            // Derive shared AES key
            byte[] sharedSecret = CryptoUtils.performECDH(keyPair.getPrivate(), clientPubKey);
            aesKey = CryptoUtils.deriveAESKey(sharedSecret);

            System.out.println("Secure channel established! Start typing:");

            // Receive messages in background thread
            new Thread(() -> {
                try {
                    String line;
                    while ((line = in.readLine()) != null) {
                        byte[] data = Base64.getDecoder().decode(line);
                        String message = CryptoUtils.decrypt(data, aesKey);
                        System.out.println("Client: " + message);
                    }
                } catch (Exception e) {
                    System.out.println("Client disconnected.");
                }
            }).start();

            // Send messages from console
            try (BufferedReader console = new BufferedReader(new InputStreamReader(System.in))) {
                String input;
                while ((input = console.readLine()) != null) {
                    if ("exit".equalsIgnoreCase(input)) break;
                    byte[] encrypted = CryptoUtils.encrypt(input, aesKey);
                    out.println(Base64.getEncoder().encodeToString(encrypted));
                }
            }
        } finally {
            serverSocket.close();
        }
    }
}
