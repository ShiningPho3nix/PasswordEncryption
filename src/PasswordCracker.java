import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TODO Kommentare schreiben
 * 
 * @author Steffen Dworsky, Ramón Schultz
 *
 */
public class PasswordCracker {

	static byte[] salt;
	static public String pass;

	public static void main(String[] args) {
		String hash = args[0];

		salt = args[1].getBytes();

		char[] charset = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
		Arrays.sort(charset);
		PasswordCracker bf = new PasswordCracker(charset, 1);

		while (true) {

			String attempt = bf.toString();
			pass = bf.toString();
			// System.out.println(attempt);
			attempt = getSecurePassword(attempt, salt);
			// System.out.println("" + attempt);

			if (attempt.equals(hash)) {
				System.out.println("Password Found: " + pass);
				break;
			}
			bf.increment();
		}
	}

	private char[] cs; // Character Set
	private char[] cg; // Current Guess

	public PasswordCracker(char[] characterSet, int guessLength) {
		cs = characterSet;
		cg = new char[guessLength];
		Arrays.fill(cg, cs[0]);
	}

	public void increment() {
		int index = cg.length - 1;
		while (index >= 0) {
			if (cg[index] == cs[cs.length - 1]) {
				if (index == 0) {
					cg = new char[cg.length + 1];
					Arrays.fill(cg, cs[0]);
					System.out.println(pass);
					break;
				} else {
					cg[index] = cs[0];
					index--;
				}
			} else {
				cg[index] = cs[Arrays.binarySearch(cs, cg[index]) + 1];
				break;
			}
		}
	}

	@Override
	public String toString() {
		return String.valueOf(cg);
	}

	private static String getSecurePassword(String passwordToHash, byte[] salt) {
		String generatedPassword = null;
		try {
			// Create MessageDigest instance for MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			// Add password bytes to digest
			md.update(salt);
			// Get the hash's bytes
			byte[] bytes = md.digest(passwordToHash.getBytes());
			// This bytes[] has bytes in decimal format;
			// Convert it to hexadecimal format
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			// Get complete hashed password in hex format
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatedPassword;
	}

	// converts a char[] to byte[] without creating a string.
//    private static byte[] toBytes(char[] chars) {
//        CharBuffer charBuffer = CharBuffer.wrap(chars);
//        ByteBuffer byteBuffer = Charset.defaultCharset().encode(charBuffer);
//        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
//                byteBuffer.position(), byteBuffer.limit());
//        Arrays.fill(charBuffer.array(), '\u0000'); // clear sensitive data
//        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
//        return bytes;
//    }   
}