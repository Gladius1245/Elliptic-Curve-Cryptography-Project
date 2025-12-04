// Caleb Gildehaus - Final Project for Computer Science
// Start date: 11/7/2025
// Secure ECC Chat Application using ECDH + AES-256-GCM

package com.example;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Secure ECC Chat");
        System.out.println("1. Start Server");
        System.out.println("2. Start Client");
        System.out.print("Choose (1 or 2): ");

        String choice = scanner.nextLine().trim();

        if ("1".equals(choice)) {
            System.out.println("Starting server on port 5000...");
            new ChatServer().start(5000);
        } else if ("2".equals(choice)) {
            System.out.println("Connecting to server at localhost:5000...");
            new ChatClient().connect("localhost", 5000);
        } else {
            System.out.println("Invalid choice. Please enter 1 or 2.");
        }
    }
}