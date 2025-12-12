import java.io.*;
import java.net.*;
import java.util.*;
import java.security.SecureRandom;

public class CipherServerClient {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Choose mode: (1) Server (2) Client)");
        int mode = 1;
        try { mode = Integer.parseInt(scanner.nextLine().trim()); } catch (Exception e) {}
        if (mode == 1) startServer();
        else startClient(scanner);
        scanner.close();
    }

    private static void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            System.out.println("Server listening on 12345");
            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    System.out.println("Client connected: " + socket.getInetAddress());
                    handleClient(socket);
                } catch (IOException e) { e.printStackTrace(); }
            }
        } catch (IOException e) { e.printStackTrace(); }
    }

    private static void handleClient(Socket socket) {
        try (BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter output = new PrintWriter(socket.getOutputStream(), true)) {
            String command;
            while ((command = input.readLine()) != null) {
                output.println(process(command));
            }
        } catch (IOException e) { e.printStackTrace(); }
    }

    private static void startClient(Scanner scanner) {
        System.out.println("Server host (default localhost):");
        String host = scanner.nextLine().trim();
        if (host.isEmpty()) host = "localhost";
        System.out.println("Server port (default 12345):");
        String portString = scanner.nextLine().trim();
        int port = portString.isEmpty() ? 12345 : Integer.parseInt(portString);

        try (Socket socket = new Socket(host, port);
             BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter output = new PrintWriter(socket.getOutputStream(), true)) {

            while (true) {
                System.out.println("\nChoose cipher:");
                System.out.println("1) Caesar");
                System.out.println("2) Monoalphabetic");
                System.out.println("3) Playfair");
                System.out.println("4) Hill (2x2)");
                System.out.println("5) Vigenère");
                System.out.println("6) One-Time Pad (hex key:cipher)");
                System.out.println("7) Rail Fence");
                System.out.println("0) Exit");
                System.out.print("Selection: ");
                String selection = scanner.nextLine().trim();
                if (selection.equals("0")) break;

                String cipherName = switch (selection) {
                    case "1" -> "caesar";
                    case "2" -> "monoalphabetic";
                    case "3" -> "playfair";
                    case "4" -> "hill";
                    case "5" -> "vigenere";
                    case "6" -> "one-time-pad";
                    case "7" -> "rail-fence";
                    default -> "";
                };
                if (cipherName.isEmpty()) { System.out.println("Invalid choice."); continue; }

                System.out.print("Operation (encrypt/decrypt): ");
                String operation = scanner.nextLine().trim().toLowerCase();
                if (!operation.equals("encrypt") && !operation.equals("decrypt")) { System.out.println("Invalid operation."); continue; }

                System.out.print("Enter text: ");
                String text = scanner.nextLine();

                String extraParam = "";
                if (cipherName.equals("caesar")) {
                    System.out.print("Shift (default 3): ");
                    String shift = scanner.nextLine().trim();
                    extraParam = shift.isEmpty() ? "3" : shift;
                } else if (cipherName.equals("playfair") || cipherName.equals("vigenere")) {
                    System.out.print("Keyword (default 'keyword'): ");
                    String keyword = scanner.nextLine().trim();
                    extraParam = keyword.isEmpty() ? "keyword" : keyword;
                } else if (cipherName.equals("hill")) {
                    System.out.println("Enter 2x2 key matrix values a b c d (row-major), default '6 24 1 13':");
                    String line = scanner.nextLine().trim();
                    extraParam = line.isEmpty() ? "6 24 1 13" : line;
                } else if (cipherName.equals("rail-fence")) {
                    System.out.print("Number of rails (default 2): ");
                    String rails = scanner.nextLine().trim();
                    extraParam = rails.isEmpty() ? "2" : rails;
                } else if (cipherName.equals("one-time-pad") && operation.equals("encrypt")) {
                    System.out.print("Hex key (optional, provide hex key to use; leave blank to let server generate): ");
                    String key = scanner.nextLine().trim();
                    if (!key.isEmpty()) extraParam = key;
                }

                StringBuilder commandBuilder = new StringBuilder();
                commandBuilder.append(operation).append(" ").append(cipherName);
                if (!extraParam.isEmpty()) commandBuilder.append(" ").append(extraParam);
                if (!text.isEmpty()) commandBuilder.append(" ").append(text.replace("\n", " ").replace("\r", ""));
                output.println(commandBuilder.toString());
                String response = input.readLine();
                if (response == null) { System.out.println("Server disconnected."); break; }
                System.out.println("Server: " + response);
            }

        } catch (IOException e) { e.printStackTrace(); }
    }

    private static String process(String command) {
        command = command == null ? "" : command.trim();
        if (command.isEmpty()) return "Empty command.";

        String operation, cipher, remainder;
        int firstSpace = command.indexOf(' ');
        if (firstSpace == -1) return "Invalid command.";
        operation = command.substring(0, firstSpace).trim();
        int secondSpace = command.indexOf(' ', firstSpace + 1);
        if (secondSpace == -1) return "Invalid command (missing cipher).";
        cipher = command.substring(firstSpace + 1, secondSpace).trim();
        remainder = command.substring(secondSpace + 1).trim();

        try {
            if (operation.equalsIgnoreCase("encrypt")) return processEnc(cipher.toLowerCase(), remainder);
            if (operation.equalsIgnoreCase("decrypt")) return processDec(cipher.toLowerCase(), remainder);
            return "Unknown operation.";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private static String processEnc(String cipher, String remainder) {
        String param = "";
        String text = "";

        if (cipher.equals("hill")) {
            String[] tokens = remainder.split("\\s+");
            if (tokens.length >= 4) {
                param = String.join(" ", Arrays.copyOfRange(tokens, 0, 4));
                if (tokens.length > 4) text = joinRange(tokens, 4, tokens.length);
            } else {
                param = "";
                text = remainder;
            }
        } else if (cipher.equals("caesar") || cipher.equals("rail-fence")) {
            String[] tokens = remainder.split("\\s+", 2);
            if (tokens.length == 0) { text = ""; param = ""; }
            else if (tokens.length == 1) {
                text = tokens[0];
                param = "";
            } else {
                if (isInteger(tokens[0])) {
                    param = tokens[0];
                    text = tokens[1];
                } else {
                    param = "";
                    text = remainder;
                }
            }
        } else if (cipher.equals("playfair") || cipher.equals("vigenere")) {
            String[] tokens = remainder.split("\\s+", 2);
            if (tokens.length == 0) { param = ""; text = ""; }
            else if (tokens.length == 1) { param = tokens[0]; text = ""; }
            else { param = tokens[0]; text = tokens[1]; }
        } else if (cipher.equals("monoalphabetic")) {
            param = "";
            text = remainder;
        } else if (cipher.equals("one-time-pad")) {
            String[] tokens = remainder.split("\\s+", 2);
            if (tokens.length == 0) { param = ""; text = ""; }
            else if (tokens.length == 1) {
                param = "";
                text = tokens[0];
            } else {
                if (looksLikeHex(tokens[0])) {
                    param = tokens[0];
                    text = tokens[1];
                } else {
                    param = "";
                    text = remainder;
                }
            }
        } else {
            String[] tokens = remainder.split("\\s+", 2);
            if (tokens.length == 0) { param = ""; text = ""; }
            else if (tokens.length == 1) { param = tokens[0]; text = ""; }
            else { param = tokens[0]; text = tokens[1]; }
        }

        if ((cipher.equals("monoalphabetic") || cipher.equals("one-time-pad")) && text.isEmpty()) {
            text = param;
            param = "";
        }

        switch (cipher) {
            case "caesar":
                int shift = param.isEmpty() ? 3 : Integer.parseInt(param);
                return Caesar.enc(text, shift);
            case "monoalphabetic":
                return Mono.enc(text);
            case "playfair":
                return Playfair.enc(text, param.isEmpty() ? "keyword" : param);
            case "hill": {
                int[] values = parseInts(param, new int[]{6,24,1,13});
                return Hill.enc(text, new int[][]{{values[0],values[1]},{values[2],values[3]}});
            }
            case "vigenere":
                return Vig.enc(text, param.isEmpty() ? "keyword" : param);
            case "one-time-pad":
                return OTP.enc(text, param);
            case "rail-fence":
                int rails = param.isEmpty() ? 2 : Integer.parseInt(param);
                return Rail.enc(text, rails);
            default:
                return "Unknown cipher.";
        }
    }

    private static String processDec(String cipher, String remainder) {
        String param = "";
        String text = "";

        if (cipher.equals("hill")) {
            String[] tokens = remainder.split("\\s+");
            if (tokens.length >= 4) {
                param = String.join(" ", Arrays.copyOfRange(tokens, 0, 4));
                if (tokens.length > 4) text = joinRange(tokens, 4, tokens.length);
            } else {
                param = "";
                text = remainder;
            }
        } else if (cipher.equals("caesar") || cipher.equals("rail-fence")) {
            String[] tokens = remainder.split("\\s+", 2);
            if (tokens.length == 0) { text = ""; param = ""; }
            else if (tokens.length == 1) { text = tokens[0]; param = ""; }
            else {
                if (isInteger(tokens[0])) {
                    param = tokens[0];
                    text = tokens[1];
                } else {
                    param = "";
                    text = remainder;
                }
            }
        } else if (cipher.equals("playfair") || cipher.equals("vigenere")) {
            String[] tokens = remainder.split("\\s+", 2);
            if (tokens.length == 0) { param = ""; text = ""; }
            else if (tokens.length == 1) { param = tokens[0]; text = ""; }
            else { param = tokens[0]; text = tokens[1]; }
        } else if (cipher.equals("monoalphabetic")) {
            param = "";
            text = remainder;
        } else if (cipher.equals("one-time-pad")) {
            if (remainder.contains(":")) {
                text = remainder;
                param = "";
            } else {
                String[] tokens = remainder.split("\\s+", 2);
                if (tokens.length == 1) {
                    text = tokens[0];
                } else {
                    param = tokens[0];
                    text = tokens[1];
                    text = param + ":" + text;
                    param = "";
                }
            }
        } else {
            String[] tokens = remainder.split("\\s+", 2);
            if (tokens.length == 0) { param = ""; text = ""; }
            else if (tokens.length == 1) { param = tokens[0]; text = ""; }
            else { param = tokens[0]; text = tokens[1]; }
        }

        if ((cipher.equals("monoalphabetic") || cipher.equals("one-time-pad")) && text.isEmpty()) {
            text = param;
            param = "";
        }

        switch (cipher) {
            case "caesar":
                int shift = param.isEmpty() ? 3 : Integer.parseInt(param);
                return Caesar.dec(text, shift);
            case "monoalphabetic":
                return Mono.dec(text);
            case "playfair":
                return Playfair.dec(text, param.isEmpty() ? "keyword" : param);
            case "hill": {
                int[] values = parseInts(param, new int[]{6,24,1,13});
                return Hill.dec(text, new int[][]{{values[0],values[1]},{values[2],values[3]}});
            }
            case "vigenere":
                return Vig.dec(text, param.isEmpty() ? "keyword" : param);
            case "one-time-pad":
                return OTP.dec(text);
            case "rail-fence":
                int rails = param.isEmpty() ? 2 : Integer.parseInt(param);
                return Rail.dec(text, rails);
            default:
                return "Unknown cipher.";
        }
    }

    private static boolean isInteger(String value) {
        try { Integer.parseInt(value); return true; } catch (Exception e) { return false; }
    }
    private static boolean looksLikeHex(String value) {
        return value.matches("(?i)^[0-9a-f]+$");
    }
    private static String joinRange(String[] array, int from, int to) {
        if (from >= to) return "";
        StringBuilder result = new StringBuilder();
        for (int i = from; i < to; i++) {
            if (result.length() > 0) result.append(' ');
            result.append(array[i]);
        }
        return result.toString();
    }
    private static int[] parseInts(String input, int[] defaultValues) {
        if (input == null || input.isEmpty()) return defaultValues;
        String[] tokens = input.trim().split("\\s+");
        int[] output = new int[Math.max(tokens.length, defaultValues.length)];
        for (int i = 0; i < output.length; i++) output[i] = i < tokens.length ? Integer.parseInt(tokens[i]) : (i < defaultValues.length ? defaultValues[i] : 0);
        return output;
    }

    static class Caesar {
        static String enc(String text, int shift) {
            StringBuilder result = new StringBuilder();
            shift = ((shift % 26) + 26) % 26;
            for (char c : text.toCharArray()) {
                if (Character.isLetter(c)) {
                    char base = Character.isLowerCase(c) ? 'a' : 'A';
                    result.append((char)((c - base + shift) % 26 + base));
                } else result.append(c);
            }
            return result.toString();
        }
        static String dec(String text, int shift) { return enc(text, 26 - ((shift%26+26)%26)); }
    }

    static class Mono {
        private static final String PLAIN = "abcdefghijklmnopqrstuvwxyz";
        private static final String CIPHER = "phqgiumeaylnofdxjkrcvstzwb";
        static String enc(String text) {
            StringBuilder result = new StringBuilder();
            for (char ch : text.toCharArray()) {
                if (Character.isLetter(ch)) {
                    boolean isLower = Character.isLowerCase(ch);
                    char mapped = map(Character.toLowerCase(ch), PLAIN, CIPHER);
                    result.append(isLower ? mapped : Character.toUpperCase(mapped));
                } else result.append(ch);
            }
            return result.toString();
        }
        static String dec(String text) {
            StringBuilder result = new StringBuilder();
            for (char ch : text.toCharArray()) {
                if (Character.isLetter(ch)) {
                    boolean isLower = Character.isLowerCase(ch);
                    char mapped = map(Character.toLowerCase(ch), CIPHER, PLAIN);
                    result.append(isLower ? mapped : Character.toUpperCase(mapped));
                } else result.append(ch);
            }
            return result.toString();
        }
        private static char map(char character, String from, String to) {
            int index = from.indexOf(character);
            return index >= 0 ? to.charAt(index) : character;
        }
    }

    static class Playfair {
        private static char[][] keySquare(String key) {
            key = key == null ? "" : key.toLowerCase().replaceAll("[^a-z]", "").replace('j','i');
            StringBuilder chars = new StringBuilder();
            for (char c : key.toCharArray()) if (chars.indexOf(String.valueOf(c)) == -1) chars.append(c);
            for (char c='a'; c<='z'; c++) if (c!='j' && chars.indexOf(String.valueOf(c))==-1) chars.append(c);
            char[][] square = new char[5][5];
            for (int i=0;i<25;i++) square[i/5][i%5] = chars.charAt(i);
            return square;
        }
        private static String prep(String text, boolean isEncrypt) {
            text = text == null ? "" : text.toLowerCase().replaceAll("[^a-z]", "").replace('j','i');
            StringBuilder prepared = new StringBuilder();
            for (int i=0;i<text.length();i++) {
                char current = text.charAt(i);
                if (isEncrypt && i+1 < text.length() && current == text.charAt(i+1)) {
                    prepared.append(current).append('x');
                } else prepared.append(current);
            }
            if (isEncrypt && prepared.length()%2==1) prepared.append('x');
            return prepared.toString();
        }
        private static int[] pos(char[][] square, char c) {
            for (int row=0;row<5;row++) for (int col=0;col<5;col++) if (square[row][col]==c) return new int[]{row,col};
            return null;
        }
        static String enc(String text, String key) {
            char[][] square = keySquare(key);
            String prepared = prep(text, true);
            StringBuilder output = new StringBuilder();
            for (int i=0;i<prepared.length();i+=2) {
                char first = prepared.charAt(i), second = prepared.charAt(i+1);
                int[] posFirst = pos(square,first), posSecond = pos(square,second);
                if (posFirst[0]==posSecond[0]) {
                    output.append(square[posFirst[0]][(posFirst[1]+1)%5]).append(square[posSecond[0]][(posSecond[1]+1)%5]);
                } else if (posFirst[1]==posSecond[1]) {
                    output.append(square[(posFirst[0]+1)%5][posFirst[1]]).append(square[(posSecond[0]+1)%5][posSecond[1]]);
                } else {
                    output.append(square[posFirst[0]][posSecond[1]]).append(square[posSecond[0]][posFirst[1]]);
                }
            }
            return output.toString();
        }
        static String dec(String text, String key) {
            char[][] square = keySquare(key);
            String prepared = text == null ? "" : text.toLowerCase().replaceAll("[^a-z]", "");
            StringBuilder output = new StringBuilder();
            for (int i=0;i<prepared.length();i+=2) {
                char first = prepared.charAt(i), second = prepared.charAt(i+1);
                int[] posFirst = pos(square,first), posSecond = pos(square,second);
                if (posFirst[0]==posSecond[0]) {
                    output.append(square[posFirst[0]][(posFirst[1]+4)%5]).append(square[posSecond[0]][(posSecond[1]+4)%5]);
                } else if (posFirst[1]==posSecond[1]) {
                    output.append(square[(posFirst[0]+4)%5][posFirst[1]]).append(square[(posSecond[0]+4)%5][posSecond[1]]);
                } else {
                    output.append(square[posFirst[0]][posSecond[1]]).append(square[posSecond[0]][posFirst[1]]);
                }
            }
            return output.toString();
        }
    }

    static class Hill {
        static String enc(String text, int[][] key) {
            text = text == null ? "" : text.toLowerCase().replaceAll("[^a-z]",""); if (text.length()%2==1) text += 'x';
            StringBuilder output = new StringBuilder();
            for (int i=0;i<text.length();i+=2) {
                int first = text.charAt(i)-'a', second = text.charAt(i+1)-'a';
                int result0 = (key[0][0]*first + key[0][1]*second) % 26;
                int result1 = (key[1][0]*first + key[1][1]*second) % 26;
                if (result0<0) result0+=26;
                if (result1<0) result1+=26;
                output.append((char)(result0+'a')).append((char)(result1+'a'));
            }
            return output.toString();
        }
        private static int inv(int value, int modulus) {
            value = (value % modulus + modulus) % modulus;
            for (int x=1;x<modulus;x++) if ((value*x)%modulus==1) return x;
            return -1;
        }
        private static int[][] invKey(int[][] key) {
            int determinant = (key[0][0]*key[1][1] - key[0][1]*key[1][0]) % 26;
            if (determinant<0) determinant+=26;
            int inverseDet = inv(determinant,26);
            if (inverseDet == -1) throw new IllegalArgumentException("Key matrix not invertible mod 26");
            int[][] adjugate = new int[][]{
                {key[1][1], (26 - key[0][1]) % 26},
                {(26 - key[1][0]) % 26, key[0][0]}
            };
            int[][] inverse = new int[2][2];
            for (int i = 0; i < 2; i++)
                for (int j = 0; j < 2; j++)
                    inverse[i][j] = (adjugate[i][j] * inverseDet) % 26;
            return inverse;
        }
        static String dec(String text, int[][] key) {
            int[][] inverseKey = invKey(key);
            StringBuilder output = new StringBuilder();
            text = text == null ? "" : text.toLowerCase().replaceAll("[^a-z]","");
            if (text.length()%2==1) text += 'x';
            for (int i=0;i<text.length();i+=2) {
                int first = text.charAt(i)-'a', second = text.charAt(i+1)-'a';
                int result0 = (inverseKey[0][0]*first + inverseKey[0][1]*second) % 26;
                int result1 = (inverseKey[1][0]*first + inverseKey[1][1]*second) % 26;
                if (result0<0) result0+=26;
                if (result1<0) result1+=26;
                output.append((char)(result0+'a')).append((char)(result1+'a'));
            }
            return output.toString();
        }
    }

    static class Vig {
        private static String normKey(String key) {
            String normalized = (key==null? "": key).toLowerCase().replaceAll("[^a-z]","");
            if (normalized.isEmpty()) normalized = "keyword";
            return normalized;
        }
        static String enc(String text, String key) {
            String normalizedKey = normKey(key);
            StringBuilder output = new StringBuilder();
            int keyIndex = 0;
            for (int i=0;i<text.length();i++) {
                char c = text.charAt(i);
                if (Character.isLetter(c)) {
                    char base = Character.isLowerCase(c) ? 'a' : 'A';
                    int shift = normalizedKey.charAt(keyIndex % normalizedKey.length()) - 'a';
                    output.append((char)((c - base + shift) % 26 + base));
                    keyIndex++;
                } else {
                    output.append(c);
                }
            }
            return output.toString();
        }
        static String dec(String text, String key) {
            String normalizedKey = normKey(key);
            StringBuilder output = new StringBuilder();
            int keyIndex = 0;
            for (int i=0;i<text.length();i++) {
                char c = text.charAt(i);
                if (Character.isLetter(c)) {
                    char base = Character.isLowerCase(c) ? 'a' : 'A';
                    int shift = normalizedKey.charAt(keyIndex % normalizedKey.length()) - 'a';
                    output.append((char)((c - base - shift + 26) % 26 + base));
                    keyIndex++;
                } else {
                    output.append(c);
                }
            }
            return output.toString();
        }
    }

    static class OTP {
        private static final SecureRandom random = new SecureRandom();

        static String enc(String text, String hexKeyProvided) {
            try {
                byte[] plaintext = text.getBytes("UTF-8");
                if (hexKeyProvided == null || hexKeyProvided.isEmpty()) {
                    byte[] key = new byte[plaintext.length];
                    random.nextBytes(key);
                    byte[] ciphertext = xor(plaintext, key);
                    return bytesToHex(key) + ":" + bytesToHex(ciphertext);
                } else {
                    byte[] key = hexToBytes(hexKeyProvided);
                    if (key.length < plaintext.length) {
                        throw new IllegalArgumentException("Provided key too short for plaintext");
                    }
                    byte[] keyUsed = Arrays.copyOf(key, plaintext.length);
                    byte[] ciphertext = xor(plaintext, keyUsed);
                    return bytesToHex(ciphertext);
                }
            } catch (UnsupportedEncodingException e) {
                return "Error: " + e.getMessage();
            }
        }

        static String dec(String text) {
            try {
                if (!text.contains(":")) throw new IllegalArgumentException("For OTP decryption provide 'hexkey:hexcipher' or 'hexkey hexcipher'");
                String[] parts = text.split(":", 2);
                byte[] key = hexToBytes(parts[0]);
                byte[] ciphertext = hexToBytes(parts[1]);
                if (key.length < ciphertext.length) throw new IllegalArgumentException("Key shorter than cipher");
                byte[] keyUsed = Arrays.copyOf(key, ciphertext.length);
                byte[] plaintext = xor(ciphertext, keyUsed);
                return new String(plaintext, "UTF-8");
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        private static byte[] xor(byte[] first, byte[] second) {
            byte[] output = new byte[first.length];
            for (int i=0;i<first.length;i++) output[i] = (byte)(first[i] ^ second[i]);
            return output;
        }

        private static String bytesToHex(byte[] bytes) {
            StringBuilder hex = new StringBuilder(bytes.length*2);
            for (byte b : bytes) hex.append(String.format("%02x", b & 0xff));
            return hex.toString();
        }

        private static byte[] hexToBytes(String hex) {
            hex = hex.replaceAll("\\s+", "");
            if (hex.length() % 2 == 1) throw new IllegalArgumentException("Invalid hex string");
            int length = hex.length() / 2;
            byte[] output = new byte[length];
            for (int i=0;i<length;i++) {
                int index = i*2;
                output[i] = (byte) Integer.parseInt(hex.substring(index, index+2), 16);
            }
            return output;
        }
    }

    static class Rail {
        static String enc(String text, int rails) {
            if (rails <= 1) return text;
            StringBuilder[] railLines = new StringBuilder[rails];
            for (int i=0;i<rails;i++) railLines[i] = new StringBuilder();
            int currentRail = 0, direction = 1;
            for (char c : text.toCharArray()) {
                railLines[currentRail].append(c);
                currentRail += direction;
                if (currentRail == rails-1) direction = -1;
                else if (currentRail == 0) direction = 1;
            }
            StringBuilder output = new StringBuilder();
            for (StringBuilder line : railLines) output.append(line);
            return output.toString();
        }

        static String dec(String text, int rails) {
            if (rails <= 1) return text;
            int length = text.length();
            int currentRail = 0, direction = 1;
            int[] counts = new int[rails];
            for (int i = 0; i < length; i++) {
                counts[currentRail]++;
                currentRail += direction;
                if (currentRail == rails-1) direction = -1;
                else if (currentRail == 0) direction = 1;
            }
            String[] railsContent = new String[rails];
            int index = 0;
            for (int i = 0; i < rails; i++) {
                int count = counts[i];
                railsContent[i] = text.substring(index, index + count);
                index += count;
            }
            StringBuilder plaintext = new StringBuilder();
            int[] positionInRail = new int[rails];
            currentRail = 0; direction = 1;
            for (int i = 0; i < length; i++) {
                plaintext.append( railsContent[currentRail].charAt(positionInRail[currentRail]++) );
                currentRail += direction;
                if (currentRail == rails-1) direction = -1;
                else if (currentRail == 0) direction = 1;
            }
            return plaintext.toString();
        }
    }
}
