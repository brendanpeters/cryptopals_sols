
import org.apache.commons.codec.DecoderException;

public class Set1 {
	public static void main(String[] a) {
		System.out.println("Challenge 1: " + challenge1());
		System.out.println("Challenge 2: " + challenge2());
		System.out.println("Challenge 3: ");
		challenge3();
		System.out.println("DONE");
	}

	private static boolean challenge1() {
		try {
			return "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".equals(CryptoUtils.hex2base64(
					"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));
		} catch (DecoderException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static boolean challenge2() {
		try {
			return "746865206b696420646f6e277420706c6179".equals(CryptoUtils
					.fixedXor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"));
		} catch (DecoderException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static void challenge3() {
		String input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
		try {
			char k = CryptoUtils.findKeyXorSingleChar(input);
			System.out.println(CryptoUtils.xorSingleChar(input, k));
			System.out.println("=============================");
			for (Character c : CryptoUtils.CHAR_FREQ_TBL.keySet()) {
				System.out.println(CryptoUtils.xorSingleChar(input, c));
			}
		} catch (DecoderException e) {
			e.printStackTrace();
		}
	}

}
