import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class CryptoUtils {
	public static Map<Character, Double> CHAR_FREQ_TBL = new HashMap<Character, Double>();
	static {
		CHAR_FREQ_TBL.put('0', 12.02);
		CHAR_FREQ_TBL.put('1', 12.02);
		CHAR_FREQ_TBL.put('2', 12.02);
		CHAR_FREQ_TBL.put('3', 12.02);
		CHAR_FREQ_TBL.put('4', 12.02);
		CHAR_FREQ_TBL.put('5', 12.02);
		CHAR_FREQ_TBL.put('6', 12.02);
		CHAR_FREQ_TBL.put('7', 12.02);
		CHAR_FREQ_TBL.put('8', 12.02);
		CHAR_FREQ_TBL.put('9', 12.02);

		CHAR_FREQ_TBL.put('a', 12.02);
		CHAR_FREQ_TBL.put('b', 9.1);
		CHAR_FREQ_TBL.put('c', 8.12);
		CHAR_FREQ_TBL.put('d', 7.68);
		CHAR_FREQ_TBL.put('e', 7.31);
		CHAR_FREQ_TBL.put('f', 6.95);
		CHAR_FREQ_TBL.put('g', 6.28);
		CHAR_FREQ_TBL.put('h', 6.02);
		CHAR_FREQ_TBL.put('i', 5.92);
		CHAR_FREQ_TBL.put('j', 4.32);
		CHAR_FREQ_TBL.put('k', 3.98);
		CHAR_FREQ_TBL.put('l', 2.88);
		CHAR_FREQ_TBL.put('m', 2.71);
		CHAR_FREQ_TBL.put('n', 2.61);
		CHAR_FREQ_TBL.put('o', 2.3);
		CHAR_FREQ_TBL.put('p', 2.11);
		CHAR_FREQ_TBL.put('q', 2.09);
		CHAR_FREQ_TBL.put('r', 2.03);
		CHAR_FREQ_TBL.put('s', 1.82);
		CHAR_FREQ_TBL.put('t', 1.49);
		CHAR_FREQ_TBL.put('u', 1.11);
		CHAR_FREQ_TBL.put('v', 0.69);
		CHAR_FREQ_TBL.put('w', 0.17);
		CHAR_FREQ_TBL.put('x', 0.11);
		CHAR_FREQ_TBL.put('y', 0.1);
		CHAR_FREQ_TBL.put('z', 0.07);

		CHAR_FREQ_TBL.put('A', 12.02);
		CHAR_FREQ_TBL.put('B', 9.1);
		CHAR_FREQ_TBL.put('C', 8.12);
		CHAR_FREQ_TBL.put('D', 7.68);
		CHAR_FREQ_TBL.put('E', 7.31);
		CHAR_FREQ_TBL.put('F', 6.95);
		CHAR_FREQ_TBL.put('G', 6.28);
		CHAR_FREQ_TBL.put('H', 6.02);
		CHAR_FREQ_TBL.put('I', 5.92);
		CHAR_FREQ_TBL.put('J', 4.32);
		CHAR_FREQ_TBL.put('K', 3.98);
		CHAR_FREQ_TBL.put('L', 2.88);
		CHAR_FREQ_TBL.put('M', 2.71);
		CHAR_FREQ_TBL.put('N', 2.61);
		CHAR_FREQ_TBL.put('O', 2.3);
		CHAR_FREQ_TBL.put('P', 2.11);
		CHAR_FREQ_TBL.put('Q', 2.09);
		CHAR_FREQ_TBL.put('R', 2.03);
		CHAR_FREQ_TBL.put('S', 1.82);
		CHAR_FREQ_TBL.put('T', 1.49);
		CHAR_FREQ_TBL.put('U', 1.11);
		CHAR_FREQ_TBL.put('V', 0.69);
		CHAR_FREQ_TBL.put('W', 0.17);
		CHAR_FREQ_TBL.put('X', 0.11);
		CHAR_FREQ_TBL.put('Y', 0.1);
		CHAR_FREQ_TBL.put('Z', 0.07);
	}

	public static void main(String[] args) {
		System.out.println(scoreCharFreq("abc"));
		System.out.println((char) ('a' ^ '\u0000'));
		System.out.println((char) ('b' ^ 'a'));
		System.out.println((char) ('c' ^ 'a'));
		try {
//			System.out.println(xorSingleChar("abc", '\u0000'));
			System.out.println(Arrays.toString(Hex.decodeHex("656667")));
		} catch (DecoderException e) {
			e.printStackTrace();
		}
	}

	public static String fixedXor(String s1, String s2) throws DecoderException {
		byte[] b1 = Hex.decodeHex(s1);
		byte[] b2 = Hex.decodeHex(s2);
		return Hex.encodeHexString(xorByteArrays(b1, b2));
	}

	public static byte[] xorByteArrays(byte[] b1, byte[] b2) {
		if (b1.length != b2.length) {
			throw new IllegalArgumentException("Input arrays must be same length");
		}
		byte[] output = new byte[b1.length];
		for (int i = 0; i < b1.length; i++) {
			output[i] = (byte) (b1[i] ^ b2[i]);
		}
		return output;
	}

	public static String hex2base64(String input) throws DecoderException {
		byte[] decodedHex = Hex.decodeHex(input);
		return Base64.encodeBase64String(decodedHex);
	}

	public static String xorSingleChar(String input, char c) throws DecoderException {
		String s = new StringBuilder().append(c).append(c).toString();
		byte[] decodedHex = Hex.decodeHex(input);
		byte b = Hex.decodeHex(s)[0];
		byte[] output = new byte[decodedHex.length];
		for (int i = 0; i < decodedHex.length; i++) {
			output[i] = (byte) (decodedHex[i] ^ b);
		}
		return Hex.encodeHexString(output);
	}
//	public static String xorSingleChar(String input, char c) throws DecoderException {
//		String output = "";
//		for (int i = 0; i < input.length(); i++) {
//			output += (char) (input.charAt(i) ^ c);
//		}
//		return output;
//	}

	public static double scoreCharFreq(String input) {
		double output = 0;
		Double d;
		for (int i = 0; i < input.length(); i++) {
			d = CHAR_FREQ_TBL.get(input.charAt(i));
			output += (d == null ? 0 : d);
		}
		return output;
	}

	public static char findKeyXorSingleChar(String input) throws DecoderException {
		char key = ' ';
		double highScore = 0, score;
		String curDecrypted;
		for (Character c : CHAR_FREQ_TBL.keySet()) {
			score = scoreCharFreq(xorSingleChar(input, c));
			if (score > highScore) {
				highScore = score;
				key = c;
			}
		}
		System.out.println("highScore: " + highScore);
		System.out.println("key: " + key);
		return key;
	}

}
