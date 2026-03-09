import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

class dss {
    public static void main(String[] a) throws Exception {
        if (a.length > 0 && a[0].equals("s")) {
            ServerSocket ss = new ServerSocket(6000);
            System.out.println("bank server waiting...");
            Socket s = ss.accept();
            ObjectInputStream in = new ObjectInputStream(s.getInputStream());
            String msg = (String) in.readObject();
            byte[] sig = (byte[]) in.readObject();
            PublicKey pk = (PublicKey) in.readObject();
            System.out.println("received transaction: " + msg);
            System.out.println("received signature (" + sig.length + " bytes):");
            StringBuilder sb = new StringBuilder();
            for (byte b : sig) sb.append(String.format("%02X", b));
            System.out.println(sb);
            System.out.println("received public key: " + pk);
            Signature v = Signature.getInstance("SHA256withDSA");
            v.initVerify(pk);
            v.update(msg.getBytes("UTF-8"));
            boolean ok = v.verify(sig);
            System.out.println("signature valid: " + ok);
            if (ok)
                System.out.println("transaction authenticated. processing: " + msg);
            else
                System.out.println("signature invalid! transaction rejected.");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(msg.getBytes("UTF-8"));
            System.out.print("sha-256 hash of message: ");
            for (byte b : h) System.out.printf("%02X", b);
            System.out.println();
            in.close(); s.close(); ss.close();
        } else {
            KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
            kg.initialize(2048);
            KeyPair kp = kg.generateKeyPair();
            PrivateKey sk = kp.getPrivate();
            PublicKey pk = kp.getPublic();
            System.out.println("alice's key pair generated (DSA 2048-bit)");
            System.out.println("private key: " + sk);
            System.out.println("public key: " + pk);
            Scanner sc = new Scanner(System.in);
            System.out.print("enter transaction: ");
            String msg = sc.nextLine();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(msg.getBytes("UTF-8"));
            System.out.print("sha-256 hash: ");
            for (byte b : h) System.out.printf("%02X", b);
            System.out.println();
            Signature sg = Signature.getInstance("SHA256withDSA");
            sg.initSign(sk);
            sg.update(msg.getBytes("UTF-8"));
            byte[] sig = sg.sign();
            System.out.println("digital signature (" + sig.length + " bytes):");
            StringBuilder sb = new StringBuilder();
            for (byte b : sig) sb.append(String.format("%02X", b));
            System.out.println(sb);
            Socket s = new Socket("localhost", 6000);
            ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
            out.writeObject(msg);
            out.writeObject(sig);
            out.writeObject(pk);
            out.flush();
            System.out.println("transaction and signature sent to bank server.");
            out.close(); s.close();
        }
    }
}