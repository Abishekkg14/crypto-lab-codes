import java.io.*;
import java.net.*;
import java.util.*;

public class SHA512Socket {
    public static void main(String[] a) throws Exception {
        if (a.length > 0 && a[0].equals("s")) {
            ServerSocket ss = new ServerSocket(5000);
            System.out.println("server waiting...");
            Socket s = ss.accept();
            DataInputStream in = new DataInputStream(s.getInputStream());
            System.out.println("received message schedule words:");
            for (int i = 0; i < 16; i++)
                System.out.printf("W%-2d = %016X%n", i, in.readLong());
            in.close(); s.close(); ss.close();
        } else {
            Scanner sc = new Scanner(System.in);
            System.out.print("enter message: ");
            String msg = sc.nextLine();
            byte[] mb = msg.getBytes("UTF-8");
            int ml = mb.length;
            System.out.println("binary representation:");
            for (byte b : mb)
                System.out.print(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0') + " ");
            System.out.println();
            int pl = ((ml + 17 + 127) / 128) * 128;
            byte[] pb = new byte[pl];
            System.arraycopy(mb, 0, pb, 0, ml);
            pb[ml] = (byte) 0x80;
            long bl = (long) ml * 8;
            for (int i = 0; i < 8; i++)
                pb[pl - 1 - i] = (byte) (bl >>> (i * 8));
            long[] w = new long[16];
            for (int i = 0; i < 16; i++)
                for (int j = 0; j < 8; j++)
                    w[i] = (w[i] << 8) | (pb[i * 8 + j] & 0xFF);
            System.out.println("sha-512 preprocessed words (W0-W15):");
            for (int i = 0; i < 16; i++)
                System.out.printf("W%-2d = %016X%n", i, w[i]);
            Socket s = new Socket("localhost", 5000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            for (int i = 0; i < 16; i++)
                out.writeLong(w[i]);
            out.flush(); out.close(); s.close();
            System.out.println("words sent to server.");
        }
    }
}
