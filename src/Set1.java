
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class Set1 {
	public static void main(String[] a) {
		System.out.println("Challenge 1: " + challenge1());
		System.out.println("Challenge 2: " + challenge2());
		System.out.println("Challenge 3: ");
		challenge3();
		try {
			challenge4();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("Challenge 5: " + challenge5());
		try {
			challenge6();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (DecoderException e) {
			e.printStackTrace();
		}
		System.out.println("DONE");
	}

	private static boolean challenge1() {
		try {
			return "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
					.equals(CryptoUtils.hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));
		} catch (DecoderException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static boolean challenge2() {
		try {
			return "746865206b696420646f6e277420706c6179".equals(CryptoUtils.fixedXor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"));
		} catch (DecoderException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static void challenge3() {
		String input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
		try {
			byte k = CryptoUtils.findKeyXorSingleChar(Hex.decodeHex(input));
			System.out.println(CryptoUtils.hex2String(CryptoUtils.xorSingleCharPretty(input, k)));
			String bonus = CryptoUtils.string2Hex("ETAOIN SHRDLU");
			System.out.println("bonus: " + bonus);
			System.out.println(CryptoUtils.hex2String(CryptoUtils.xorSingleCharPretty(bonus, k)));
			System.out.println("=============================");
		} catch (DecoderException e) {
			e.printStackTrace();
		}
	}

	private static void challenge4() throws FileNotFoundException, IOException {
		try (BufferedReader br = new BufferedReader(new FileReader("src\\rsc\\set1c4.txt"))) {
			String line;
			byte[] decodeHex;
			double maxScore = 0, score;
			byte k;
			String output = null;
			while ((line = br.readLine()) != null) {
				try {
					decodeHex = Hex.decodeHex(line);
					k = CryptoUtils.findKeyXorSingleChar(decodeHex);
					score = CryptoUtils.scoreCharFreq(CryptoUtils.xorSingleChar(decodeHex, k));
					if (score > maxScore) {
						maxScore = score;
						output = CryptoUtils.hex2String(Hex.encodeHexString(CryptoUtils.xorSingleChar(decodeHex, k)));
					}
				} catch (DecoderException e) {
					e.printStackTrace();
				}
			}
			System.out.println("=================");
			System.out.println("maxScore : " + maxScore);
			System.out.println("output : " + output);
			System.out.println("challenge 4 complete");
		}

	}

	private static boolean challenge5() {
		String input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
		String targetOutput = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
		String prettyKey = "ICE";
		byte[] k;
		byte[] msg;
		try {
			k = Hex.decodeHex(CryptoUtils.string2Hex(prettyKey));
			msg = Hex.decodeHex(CryptoUtils.string2Hex(input));
			System.out.println(">>>>>>>>>>>>>>>>>>>>>");
			System.out.println(Hex.encodeHexString(CryptoUtils.repeatingKeyXor(msg, k)));
			return targetOutput.equals(Hex.encodeHexString(CryptoUtils.repeatingKeyXor(msg, k)));
		} catch (DecoderException e) {
			e.printStackTrace();
			return false;
		}
	}

	private static void challenge6() throws FileNotFoundException, IOException, DecoderException {
		//		List<String> lines = new ArrayList<String>();
		String encB64 = "";
		try (BufferedReader br = new BufferedReader(new FileReader("src\\rsc\\s1c6.txt"))) {
			String line;
			while ((line = br.readLine()) != null) {
				//				lines.add(line);
				encB64 += line;
			}
		}
		// get longest line in file
		//		int maxLen = 0, len;
		//		for (int i = 0; i < lines.size(); i++) {
		//			len = lines.get(i).length();
		//			if (len > maxLen) {
		//				maxLen = len;
		//			}
		//		}
		//		byte[][] linesBytes = new byte[lines.size()][maxLen];
		//		for (int i = 0; i < lines.size(); i++) {
		//			linesBytes[i] = Base64.decodeBase64(lines.get(i));
		//		}
		//		System.out.println(linesBytes.length + " : " + linesBytes[0].length);
		//		System.out.println(Arrays.deepToString(linesBytes));

		byte[] enc = Base64.decodeBase64(encB64);
		System.out.println(Arrays.toString(enc));

		int maxKeySize = 40;
		byte[] sec1, sec2, sec3, sec4;
		//		int hammDist;
		double hammDistNormalized, bestScore = Double.MAX_VALUE;
		int bestKeySize = 0;
		for (int i = 2; i < maxKeySize; i++) {
			sec1 = CryptoUtils.getSubArray(enc, 0, i - 1);
			sec2 = CryptoUtils.getSubArray(enc, i, 2 * i - 1);
			sec3 = CryptoUtils.getSubArray(enc, 2 * i, 3 * i - 1);
			sec4 = CryptoUtils.getSubArray(enc, 3 * i, 4 * i - 1);
			//			hammDist = CryptoUtils.hammingDist(sec1, sec2);
			hammDistNormalized = ((double) (CryptoUtils.hammingDist(sec1, sec2) + CryptoUtils.hammingDist(sec2, sec3) + CryptoUtils.hammingDist(sec3, sec4)
					+ CryptoUtils.hammingDist(sec4, sec1))) / (4 * i);
			if (hammDistNormalized < bestScore) {
				bestScore = hammDistNormalized;
				bestKeySize = i;
			}
		}

		System.out.println("bestScore : " + bestScore);
		System.out.println("bestKeySize : " + bestKeySize);
		System.out.println(enc.length % bestKeySize);
		System.out.println("enc length : " + enc.length);

		int numBlocks = (int) Math.ceil(((double) enc.length) / bestKeySize);

		byte[][] blocksOfKeySize = new byte[numBlocks][bestKeySize];
		for (int i = 0; i < numBlocks - 1; i++) {
			for (int j = 0; j < bestKeySize; j++) {
				blocksOfKeySize[i][j] = enc[bestKeySize * i + j];
				//				System.out.println(bestKeySize * i + j);
			}
		}
		byte[][] transposed = CryptoUtils.transpose(blocksOfKeySize);
		System.out.println(Arrays.deepToString(blocksOfKeySize));
		System.out.println(Arrays.deepToString(transposed));

		// solve each block as single-character XOR
		byte[] key = new byte[bestKeySize];
		for (int i = 0; i < transposed.length; i++) {
			key[i] = CryptoUtils.findKeyXorSingleChar(transposed[i]);
		}
		System.out.println("keys : " + Arrays.toString(key));

		System.out.println(CryptoUtils.hex2String(Hex.encodeHexString(CryptoUtils.repeatingKeyXor(enc, key))));
	}

}
