import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class Set2 {

	public static void main(String[] args) {
		challenge9();
		challenge10();
		challenge11();
		challenge12();
	}

	private static void challenge9() {
		//		byte[] input = ("YELLOW SUBMARINE11111" + "YELLOW SUBMARINE11111").getBytes();
		byte[] input = "YELLOW SUBMARINE".getBytes();
		System.out.println("input len : " + input.length);
		byte[] padded = CryptoUtils.padToBlockSize(input, 16);
		System.out.println("input : " + Arrays.toString(input));
		System.out.println("padded : " + Arrays.toString(padded));
		System.out.println("final length : " + padded.length);
	}

	private static void challenge10() {
		// test ECB encrypt/decrypt
		String key = CryptoUtils.YELLOW_SUBMARINE;
		String test = "";
		for (int i = 0; i < 10; i++) {
			test += key;
		}
		try {
			byte[] enc = CryptoUtils.ecb(test.getBytes(), key.getBytes(), true);
			byte[] dec = CryptoUtils.ecb(enc, key.getBytes(), false);
			System.out.println("ECB encrypted : " + new String(enc));
			System.out.println("ECB decrypted : " + new String(dec));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

		// run CBC decryption on file
		try {
			String cipherText = CryptoUtils.readFileIntoLine(CryptoUtils.RSC_DIR_PREFIX + "s2c10.txt");
			byte[] iv = new byte[CryptoUtils.AES_BLOCK_SIZE_BYTES];
			byte[] dec = CryptoUtils.cbc(Base64.decodeBase64(cipherText), key.getBytes(), iv, false);
			System.out.println(" === BEGIN CHALLENGE 10 RESULTS === ");
			System.out.println(new String(dec));
			System.out.println("\nEncrypted again:\n");
			System.out.println(Base64.encodeBase64String(CryptoUtils.cbc(dec, key.getBytes(), iv, true)));
			System.out.println(" === END CHALLENGE 10 RESULTS === ");
		} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	private static void challenge11() {
		byte[] testInput = new byte[1000];
		try {
			byte[] enc;
			int numTests = 10, score;
			CryptoUtils.Pair<byte[], Boolean> result;
			System.out.println(" === BEGIN CHALLENGE 11 RESULTS === ");
			for (int i = 0; i < numTests; i++) {
				result = CryptoUtils.encryptionOracle(testInput);
				enc = result.x;
				score = CryptoUtils.scorePatterns(enc, CryptoUtils.AES_BLOCK_SIZE_BYTES);
				System.out.println((result.y ? "ECB" : "CBC") + " : " + score + " | Detected : " + (score > 0 ? "ECB" : "CBC"));
			}
			System.out.println(" === END CHALLENGE 11 RESULTS === ");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	private static void challenge12() {
		byte[] unknown = Base64.decodeBase64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\r\n" + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\r\n"
				+ "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\r\n" + "YnkK");
		//		byte[] unknown = (CryptoUtils.YELLOW_SUBMARINE + "|" + CryptoUtils.YELLOW_SUBMARINE + "|" + CryptoUtils.YELLOW_SUBMARINE).getBytes();
		String answer = new String(unknown);
		String test = "";
		try {
			System.out.println("^^^^^^^^^^^^^^^^^^^^^^^^^^^");
			for (int i = 0; i < 50; i++) {
				test += "A";
				System.out.println(test);
				System.out.println(Arrays.toString(CryptoUtils.encryptionOracleECB(test.getBytes(), unknown)));
			}

			int blockSize = CryptoUtils.AES_BLOCK_SIZE_BYTES;

			byte[] decrypted = CryptoUtils.byteAtATimeECBSimple(unknown, blockSize);
			System.out.println(" === BEGIN CHALLENGE 12 RESULTS === ");
			System.out.println("decrypted : ");
			System.out.println(new String(decrypted));
			System.out.println("orig : ");
			System.out.println(answer);
			System.out.println(" === ENG CHALLENGE 12 RESULTS === ");

		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}

	}

}
