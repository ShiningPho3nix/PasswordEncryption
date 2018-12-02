import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * TODO Kommentare schreiben
 * 
 * @author Steffen Dworsky, Ram�n Schultz
 *
 */
public class Useradmin {

    private static char[] password;
    private static String nutzer;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {

        String funktion = args[0];
        nutzer = args[1];
        password = args[2].toCharArray();

        if (funktion.equals("addUser")) {
            addUser();
        } else if (funktion.equals("checkUser")) {
            checkUser(nutzer, password);
        } else {
            System.out.println("Unbekannte Funktion übergeben!");
            System.out.println("Akzeptiert werden 'addUser' und 'checkUser'");
            System.exit(0);
        }

    }

    private static void checkUser(String user, char[] password) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException {

        String gesNutzer;
        String gesPass;
        String secPasswd;
        byte[] gesSalt;
        String[] daten;
        boolean noMatch = true;

        File passwordFile = new File("pass.txt");
        if (!passwordFile.exists()) {
            System.out.println("Es existieren keine Nutzer");
        }

        try (BufferedReader br = new BufferedReader(new FileReader("pass.txt"))) {

            String line = br.readLine();

            while (line != null) {

                //name und verschlüsseltes passwort
                daten = line.split(" ");
                gesNutzer = daten[0];
                gesPass = daten[1];

                //salt
                line = br.readLine();

                String[] byteValues = line.substring(1, line.length() - 1).split(",");
                byte[] bytes = new byte[byteValues.length];

                for (int i = 0, len = bytes.length; i < len; i++) {
                    bytes[i] = Byte.parseByte(byteValues[i].trim());
                }
                gesSalt = bytes;

                secPasswd = getSecurePassword(password, gesSalt);

                if (gesNutzer.equals(nutzer) && gesPass.equals(secPasswd)) {
                    System.out.println("Nutzer und Passwort existieren.");

                    noMatch = false;
                    break;
                }

                //naechste Zeile
                line = br.readLine();
            }
            if (noMatch) {
                System.out.println("Nutzername und Passwort stimmen nicht überein.");
            }

        }

        System.out.println("'checkUser' wurde ausgeführt!");

    }

    private static void addUser() throws IOException, NoSuchAlgorithmException, NoSuchProviderException {

        File passwordFile = new File("pass.txt");
        if (!passwordFile.exists()) {
            passwordFile.createNewFile();
        }

        byte[] salt = getSalt();
        String saltString = Arrays.toString(salt);

        String securePassword = getSecurePassword(password, salt);

        System.out.println(nutzer + " " + securePassword + " " + saltString);

        FileWriter fw = new FileWriter("pass.txt", true);
        fw.write(nutzer + " " + securePassword + System.lineSeparator());
        fw.write(saltString + System.lineSeparator());
        fw.close();

        System.out.println("'addUser' wurde ausgefuehrt!");

    }

    private static String getSecurePassword(char[] passwordToHash, byte[] salt) {

        //create a new char array with same contents as passwordToHash
        int len = passwordToHash.length;
        char[] copy = new char[passwordToHash.length];
        for (int x = 0; x < len; x++) {
            copy[x] = passwordToHash[x];
        }

        byte[] input = toBytes(copy);
        String generatedPassword = null;

        //hashes multiple thousand times
        for (int i = 0; i < 2345; i++) {
            try {
                // Create MessageDigest instance for MD5
                MessageDigest md = MessageDigest.getInstance("MD5");
                //Add password bytes to digest
                md.update(salt);
                //Get the hash's bytes  
                byte[] bytes;
                if (i == 0) {
                    bytes = md.digest(input);
                } else {
                    bytes = md.digest(generatedPassword.getBytes());
                }
                //This bytes[] has bytes in decimal format;
                //Convert it to hexadecimal format
                StringBuilder sb = new StringBuilder();
                for (int j = 0; j < bytes.length; j++) {
                    sb.append(Integer.toString((bytes[j] & 0xff) + 0x100, 16).substring(1));
                }
                //Get complete hashed password in hex format
                generatedPassword = sb.toString();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return generatedPassword;
    }

    //Add salt
    private static byte[] getSalt() throws NoSuchAlgorithmException, NoSuchProviderException {
        //Always use a SecureRandom generator
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
        //Create array for salt
        byte[] salt = new byte[16];
        //Get a random salt
        sr.nextBytes(salt);
        //return salt
        return salt;
    }

//    private static String hexToASCII(String hex) {
//        StringBuilder output = new StringBuilder();
//        for (int i = 0; i < hex.length(); i += 2) {
//            String str = hex.substring(i, i + 2);
//            output.append((char) Integer.parseInt(str, 16));
//        }
//        return output.toString();
//    }

    //converts a char[] to byte[] without creating a string.
    private static byte[] toBytes(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = Charset.defaultCharset().encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(charBuffer.array(), '\u0000'); // clear sensitive data
        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
        return bytes;
    }

}
