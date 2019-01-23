import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class CryptoUtils {
	public static final String RSC_DIR_PREFIX = "src\\rsc\\";
	public static Map<Character, Double> CHAR_FREQ_TBL = new HashMap<Character, Double>();
	static {
		//		CHAR_FREQ_TBL.put('0', 12.02);
		//		CHAR_FREQ_TBL.put('1', 12.02);
		//		CHAR_FREQ_TBL.put('2', 12.02);
		//		CHAR_FREQ_TBL.put('3', 12.02);
		//		CHAR_FREQ_TBL.put('4', 12.02);
		//		CHAR_FREQ_TBL.put('5', 12.02);
		//		CHAR_FREQ_TBL.put('6', 12.02);
		//		CHAR_FREQ_TBL.put('7', 12.02);
		//		CHAR_FREQ_TBL.put('8', 12.02);
		//		CHAR_FREQ_TBL.put('9', 12.02);

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

		CHAR_FREQ_TBL.put(' ', 13d);
	}

	public static Map<Character, String> CHAR_2_HEX_CHAR = new HashMap<Character, String>();
	static {
		CHAR_2_HEX_CHAR.put('a', "61");
		CHAR_2_HEX_CHAR.put('b', "62");
		CHAR_2_HEX_CHAR.put('c', "63");
		CHAR_2_HEX_CHAR.put('d', "64");
		CHAR_2_HEX_CHAR.put('e', "65");
		CHAR_2_HEX_CHAR.put('f', "66");
		CHAR_2_HEX_CHAR.put('g', "67");
		CHAR_2_HEX_CHAR.put('h', "68");
		CHAR_2_HEX_CHAR.put('i', "69");
		CHAR_2_HEX_CHAR.put('j', "6A");
		CHAR_2_HEX_CHAR.put('k', "6B");
		CHAR_2_HEX_CHAR.put('l', "6C");
		CHAR_2_HEX_CHAR.put('m', "6D");
		CHAR_2_HEX_CHAR.put('n', "6E");
		CHAR_2_HEX_CHAR.put('o', "6F");
		CHAR_2_HEX_CHAR.put('p', "70");
		CHAR_2_HEX_CHAR.put('q', "71");
		CHAR_2_HEX_CHAR.put('r', "72");
		CHAR_2_HEX_CHAR.put('s', "73");
		CHAR_2_HEX_CHAR.put('t', "74");
		CHAR_2_HEX_CHAR.put('u', "75");
		CHAR_2_HEX_CHAR.put('v', "76");
		CHAR_2_HEX_CHAR.put('w', "77");
		CHAR_2_HEX_CHAR.put('x', "78");
		CHAR_2_HEX_CHAR.put('y', "79");
		CHAR_2_HEX_CHAR.put('z', "7A");

		CHAR_2_HEX_CHAR.put('A', "41");
		CHAR_2_HEX_CHAR.put('B', "42");
		CHAR_2_HEX_CHAR.put('C', "43");
		CHAR_2_HEX_CHAR.put('D', "44");
		CHAR_2_HEX_CHAR.put('E', "45");
		CHAR_2_HEX_CHAR.put('F', "46");
		CHAR_2_HEX_CHAR.put('G', "47");
		CHAR_2_HEX_CHAR.put('H', "48");
		CHAR_2_HEX_CHAR.put('I', "49");
		CHAR_2_HEX_CHAR.put('J', "4A");
		CHAR_2_HEX_CHAR.put('K', "4B");
		CHAR_2_HEX_CHAR.put('L', "4C");
		CHAR_2_HEX_CHAR.put('M', "4D");
		CHAR_2_HEX_CHAR.put('N', "4E");
		CHAR_2_HEX_CHAR.put('O', "4F");
		CHAR_2_HEX_CHAR.put('P', "50");
		CHAR_2_HEX_CHAR.put('Q', "51");
		CHAR_2_HEX_CHAR.put('R', "52");
		CHAR_2_HEX_CHAR.put('S', "53");
		CHAR_2_HEX_CHAR.put('T', "54");
		CHAR_2_HEX_CHAR.put('U', "55");
		CHAR_2_HEX_CHAR.put('V', "56");
		CHAR_2_HEX_CHAR.put('W', "57");
		CHAR_2_HEX_CHAR.put('X', "58");
		CHAR_2_HEX_CHAR.put('Y', "59");
		CHAR_2_HEX_CHAR.put('Z', "5A");

		CHAR_2_HEX_CHAR.put('0', "30");
		CHAR_2_HEX_CHAR.put('1', "31");
		CHAR_2_HEX_CHAR.put('2', "32");
		CHAR_2_HEX_CHAR.put('3', "33");
		CHAR_2_HEX_CHAR.put('4', "34");
		CHAR_2_HEX_CHAR.put('5', "35");
		CHAR_2_HEX_CHAR.put('6', "36");
		CHAR_2_HEX_CHAR.put('7', "37");
		CHAR_2_HEX_CHAR.put('8', "38");
		CHAR_2_HEX_CHAR.put('9', "39");
		CHAR_2_HEX_CHAR.put(' ', "20");

	}
	public static Map<String, Character> HEX_CHAR_2_CHAR = new HashMap<String, Character>();
	static {
		HEX_CHAR_2_CHAR.put("61", 'a');
		HEX_CHAR_2_CHAR.put("62", 'b');
		HEX_CHAR_2_CHAR.put("63", 'c');
		HEX_CHAR_2_CHAR.put("64", 'd');
		HEX_CHAR_2_CHAR.put("65", 'e');
		HEX_CHAR_2_CHAR.put("66", 'f');
		HEX_CHAR_2_CHAR.put("67", 'g');
		HEX_CHAR_2_CHAR.put("68", 'h');
		HEX_CHAR_2_CHAR.put("69", 'i');
		HEX_CHAR_2_CHAR.put("6A", 'j');
		HEX_CHAR_2_CHAR.put("6B", 'k');
		HEX_CHAR_2_CHAR.put("6C", 'l');
		HEX_CHAR_2_CHAR.put("6D", 'm');
		HEX_CHAR_2_CHAR.put("6E", 'n');
		HEX_CHAR_2_CHAR.put("6F", 'o');
		HEX_CHAR_2_CHAR.put("70", 'p');
		HEX_CHAR_2_CHAR.put("71", 'q');
		HEX_CHAR_2_CHAR.put("72", 'r');
		HEX_CHAR_2_CHAR.put("73", 's');
		HEX_CHAR_2_CHAR.put("74", 't');
		HEX_CHAR_2_CHAR.put("75", 'u');
		HEX_CHAR_2_CHAR.put("76", 'v');
		HEX_CHAR_2_CHAR.put("77", 'w');
		HEX_CHAR_2_CHAR.put("78", 'x');
		HEX_CHAR_2_CHAR.put("79", 'y');
		HEX_CHAR_2_CHAR.put("7A", 'z');

		HEX_CHAR_2_CHAR.put("41", 'A');
		HEX_CHAR_2_CHAR.put("42", 'B');
		HEX_CHAR_2_CHAR.put("43", 'C');
		HEX_CHAR_2_CHAR.put("44", 'D');
		HEX_CHAR_2_CHAR.put("45", 'E');
		HEX_CHAR_2_CHAR.put("46", 'F');
		HEX_CHAR_2_CHAR.put("47", 'G');
		HEX_CHAR_2_CHAR.put("48", 'H');
		HEX_CHAR_2_CHAR.put("49", 'I');
		HEX_CHAR_2_CHAR.put("4A", 'J');
		HEX_CHAR_2_CHAR.put("4B", 'K');
		HEX_CHAR_2_CHAR.put("4C", 'L');
		HEX_CHAR_2_CHAR.put("4D", 'M');
		HEX_CHAR_2_CHAR.put("4E", 'N');
		HEX_CHAR_2_CHAR.put("4F", 'O');
		HEX_CHAR_2_CHAR.put("50", 'P');
		HEX_CHAR_2_CHAR.put("51", 'Q');
		HEX_CHAR_2_CHAR.put("52", 'R');
		HEX_CHAR_2_CHAR.put("53", 'S');
		HEX_CHAR_2_CHAR.put("54", 'T');
		HEX_CHAR_2_CHAR.put("55", 'U');
		HEX_CHAR_2_CHAR.put("56", 'V');
		HEX_CHAR_2_CHAR.put("57", 'W');
		HEX_CHAR_2_CHAR.put("58", 'X');
		HEX_CHAR_2_CHAR.put("59", 'Y');
		HEX_CHAR_2_CHAR.put("5A", 'Z');

		HEX_CHAR_2_CHAR.put("30", '0');
		HEX_CHAR_2_CHAR.put("31", '1');
		HEX_CHAR_2_CHAR.put("32", '2');
		HEX_CHAR_2_CHAR.put("33", '3');
		HEX_CHAR_2_CHAR.put("34", '4');
		HEX_CHAR_2_CHAR.put("35", '5');
		HEX_CHAR_2_CHAR.put("36", '6');
		HEX_CHAR_2_CHAR.put("37", '7');
		HEX_CHAR_2_CHAR.put("38", '8');
		HEX_CHAR_2_CHAR.put("39", '9');
		HEX_CHAR_2_CHAR.put("20", ' ');

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

	public static String xorSingleCharPretty(String hexString, byte k) throws DecoderException {
		return Hex.encodeHexString(xorSingleChar(Hex.decodeHex(hexString), k));
	}

	public static byte[] xorSingleChar(byte[] msg, byte k) throws DecoderException {
		byte[] output = new byte[msg.length];
		for (int i = 0; i < msg.length; i++) {
			output[i] = (byte) (msg[i] ^ k);
		}
		return output;
	}

	public static double scoreCharFreq(byte[] input) {
		double output = 0;
		Double d;
		for (int i = 0; i < input.length; i++) {
			d = CHAR_FREQ_TBL.get((char) input[i]);
			output += (d == null ? 0 : d);
		}
		return output;
	}

	public static byte findKeyXorSingleChar(byte[] input) throws DecoderException {
		return findKeyXorSingleChar(input, false);
	}
	public static byte findKeyXorSingleChar(byte[] input, boolean verbose) throws DecoderException {
		byte key = -1;
		double highScore = 0, score;
		for (byte i = 0; i < 127; i++) {
			score = scoreCharFreq(xorSingleChar(input, i));
			if (score > highScore) {
				highScore = score;
				key = i;
			}
		}
		if (verbose) {
			System.out.println("highScore: " + highScore);
			System.out.println("key: " + key);
		}
		return key;
	}

	public static String hex2String(String hexString) throws DecoderException {
		byte[] decodeHex = Hex.decodeHex(hexString);
		StringBuilder output = new StringBuilder();
		for (int i = 0; i < decodeHex.length; i++) {
			output.append((char) decodeHex[i]);
		}
		return output.toString();
	}

	public static String string2Hex(String s) {
		// convert to byte array
		int n = s.length();
		byte[] b = new byte[n];
		for (int i = 0; i < n; i++) {
			b[i] = (byte) s.charAt(i);
		}
		return Hex.encodeHexString(b);
	}
	public static byte[] repeatingKeyXor(byte[] msg, byte[] k) {
		int keyLen = k.length;
		byte[] output = new byte[msg.length];
		for (int i = 0; i < msg.length; i++) {
			output[i] = (byte) (msg[i] ^ k[i % keyLen]);
		}
		return output;
	}
	public static boolean strIs(String s) {
		return s != null && s != "";
	}
	public static int hammingDistPretty(String s1, String s2) throws DecoderException {
		String h1 = string2Hex(s1);
		String h2 = string2Hex(s2);
		return hammingDist(Hex.decodeHex(h1), Hex.decodeHex(h2));
	}
	public static int hammingDist(byte[] b1, byte[] b2) {
		if (b1.length != b2.length) {
			throw new IllegalArgumentException("Input arrays must be same length");
		}
		int output = 0;
		for (int i = 0; i < b1.length; i++) {
			output += Integer.bitCount(b1[i] ^ b2[i]);
		}
		return output;
	}

	public static byte[] getSubArray(byte[] x, int start, int end) {
		if (end < start) {
			throw new IllegalArgumentException("end must be greater than or equal to start");
		}
		byte[] output = new byte[end - start + 1];
		for (int i = start; i <= end; i++) {
			output[i - start] = x[i];
		}
		return output;
	}
	public static byte[][] transpose(byte[][] A) {
		int M = A.length;
		int N = A[0].length;
		byte[][] output = new byte[N][M];
		for (int i = 0; i < M; i++) {
			for (int j = 0; j < N; j++) {
				output[j][i] = A[i][j];
			}
		}
		return output;
	}
	public static boolean checkArraysSame(byte[] x, byte[] y) {
		if (x.length != y.length) {
			throw new IllegalArgumentException("Arrays must be same length");
		}
		for (int i = 0; i < x.length; i++) {
			if (x[i] != y[i]) {
				return false;
			}
		}
		return true;
	}

	public static String readFileIntoLine(String filePath) throws FileNotFoundException, IOException {
		String output = "";
		try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
			String line;
			while ((line = br.readLine()) != null) {
				output += line;
			}
		}
		return output;
	}
	public static List<String> readFileIntoLines(String filePath) throws FileNotFoundException, IOException {
		List<String> output = new ArrayList<String>();
		try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
			String line;
			while ((line = br.readLine()) != null) {
				output.add(line);
			}
		}
		return output;
	}

	public static void main(String[] args) {
		//		System.out.println(scoreCharFreq(Hex.decodeHex("abc")));
		System.out.println((char) ('a' ^ '\u0000'));
		System.out.println((char) ('b' ^ 'a'));
		System.out.println((char) ('c' ^ 'a'));
		try {
			//			System.out.println(xorSingleChar("abc", '\u0000'));
			byte[] decodeHex = Hex.decodeHex("656667");
			System.out.println(Arrays.toString(decodeHex));
			System.out.println(Hex.encodeHex(decodeHex));
			for (int i = 0; i < decodeHex.length; i++) {
				System.out.println((char) decodeHex[i]);
			}

			System.out.println(string2Hex("abc"));

			System.out.println((byte) 'c');
			System.out.println((char) 99);
		} catch (DecoderException e) {
			e.printStackTrace();
		}

		System.out.println("---------------------");
		try {
			System.out.println(hammingDistPretty("this is a test", "wokka wokka!!!"));
		} catch (DecoderException e) {
			e.printStackTrace();
		}
		System.out.println(Arrays.toString(Base64.decodeBase64("abcd")));
		byte[] b = { 0, 1, 2, 3, 4, 5 };
		System.out.println(Arrays.toString(getSubArray(b, 1, 3)));
	}
}
