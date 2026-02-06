import java.io.*;
import java.net.*;
import java.util.*;

public class RSASocket {
    
    // RSA Helper Methods
    static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }
    
    static int modInv(int e, int phi) {
        int d = 0, x1 = 0, x2 = 1, y1 = 1;
        int tempPhi = phi;
        
        while (e > 0) {
            int t1 = tempPhi / e;
            int t2 = tempPhi - t1 * e;
            tempPhi = e;
            e = t2;
            
            int x = x2 - t1 * x1;
            int y = d - t1 * y1;
            
            x2 = x1;
            x1 = x;
            d = y1;
            y1 = y;
        }
        
        if (tempPhi == 1) {
            return d + phi;
        }
        return -1;
    }
    
    static long modPow(long base, int exp, int mod) {
        long result = 1;
        base = base % mod;
        
        while (exp > 0) {
            if (exp % 2 == 1) {
                result = (result * base) % mod;
            }
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return result;
    }
    
    // RSA Keys Class
    static class Keys {
        int e, d, n;
        
        Keys() {
            int p = 61;
            int q = 53;
            
            n = p * q;
            int phi = (p - 1) * (q - 1);
            
            e = 17;
            while (gcd(e, phi) != 1) {
                e += 2;
            }
            
            d = modInv(e, phi);
            
            System.out.println("Generated Public Key: (e=" + e + ", n=" + n + ")");
            System.out.println("Generated Private Key: (d=" + d + ", n=" + n + ")");
        }
    }
    
    // Encryption
    static ArrayList<Integer> encrypt(String msg, int e, int n) {
        ArrayList<Integer> cipher = new ArrayList<>();
        for (int i = 0; i < msg.length(); i++) {
            int m = (int) msg.charAt(i);
            int c = (int) modPow(m, e, n);
            cipher.add(c);
        }
        return cipher;
    }
    
    // Decryption
    static String decrypt(ArrayList<Integer> cipher, int d, int n) {
        String plain = "";
        for (int c : cipher) {
            int m = (int) modPow(c, d, n);
            plain += (char) m;
        }
        return plain;
    }
    
    // Server Method
    static void runServer(int port) {
        System.out.println("=== RSA Server (Receiver) ===");
        
        Keys keys = new Keys();
        
        try {
            ServerSocket ss = new ServerSocket(port);
            System.out.println("\nServer listening on port " + port + "...");
            System.out.println("Waiting for client connection...\n");
            
            Socket s = ss.accept();
            System.out.println("Connected to client: " + s.getInetAddress());
            
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            String data = br.readLine();
            
            String[] parts = data.split(" ");
            ArrayList<Integer> cipher = new ArrayList<>();
            for (String part : parts) {
                cipher.add(Integer.parseInt(part));
            }
            
            System.out.println("\nCiphertext received: " + data);
            
            String plain = decrypt(cipher, keys.d, keys.n);
            System.out.println("Decrypted Message: " + plain + "\n");
            
            br.close();
            s.close();
            ss.close();
            
        } catch (Exception ex) {
            System.out.println("Server Error: " + ex.getMessage());
        }
    }
    
    // Client Method
    static void runClient(String msg, int port) {
        System.out.println("=== RSA Client (Sender) ===");
        
        Keys keys = new Keys();
        
        System.out.println("\nPlaintext message: " + msg);
        
        ArrayList<Integer> cipher = encrypt(msg, keys.e, keys.n);
        
        System.out.print("Ciphertext: ");
        for (int c : cipher) {
            System.out.print(c + " ");
        }
        System.out.println();
        
        try {
            Socket s = new Socket("localhost", port);
            
            PrintWriter pw = new PrintWriter(s.getOutputStream(), true);
            
            String cipherStr = "";
            for (int c : cipher) {
                cipherStr += c + " ";
            }
            
            pw.println(cipherStr.trim());
            
            System.out.println("\nMessage sent to server!");
            
            pw.close();
            s.close();
            
        } catch (ConnectException ex) {
            System.out.println("\nError: Cannot connect to server. Make sure server is running first!");
        } catch (Exception ex) {
            System.out.println("Client Error: " + ex.getMessage());
        }
    }
    
    // Main Method
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage:");
            System.out.println("  Server: java RSASocket server");
            System.out.println("  Client: java RSASocket client <message>");
            System.out.println("\nExample:");
            System.out.println("  java RSASocket server");
            System.out.println("  java RSASocket client MESSI");
            return;
        }
        
        String mode = args[0].toLowerCase();
        int port = 9999;
        
        if (mode.equals("server")) {
            runServer(port);
        } else if (mode.equals("client")) {
            if (args.length < 2) {
                System.out.println("Error: Please provide a message to send");
                System.out.println("Example: java RSASocket client RONALDO");
                return;
            }
            String msg = args[1];
            runClient(msg, port);
        } else {
            System.out.println("Invalid mode. Use 'server' or 'client'");
        }
    }
}
