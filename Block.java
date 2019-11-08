import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

//Task 4 Bitcoin mining
public class Block {

	// method for reversing the Bitcoin block header.
	private static byte[] reverseBlockHeader(byte[] blockHeader) {

		int lastElement = blockHeader.length - 1;
		/*
		 * Now reverse the header such that the zeros are at the front. iterating
		 * half-way through the array because I am only required to reverse the
		 * endianness such that it appears at the beginning of the array.
		 */
		for (int begElement = 0; begElement < blockHeader.length / 2; begElement++) {

			byte startTemp = blockHeader[begElement];
			blockHeader[begElement] = blockHeader[lastElement];
			blockHeader[lastElement] = startTemp;
			lastElement--;
		}

		return blockHeader;
	}

	public static void main(String[] args) throws Exception {

		try {
			String hashHeaderString = null;
			File blockFile = new File("block.txt");
			BufferedReader br = new BufferedReader(new FileReader(blockFile)); // read-in the file containing the
																				// Bitcoin block encoded in hex
																				// characters.
			char[] charArr = new char[160];
			br.read(charArr, 0, 160);
			String tempHeader = String.valueOf(charArr);

			byte[] byteHeaderArr = DatatypeConverter.parseHexBinary(tempHeader);

			MessageDigest digest = MessageDigest.getInstance("SHA-256");

			int nonce = 0; // will use track the nonce.

			while (true) {
				byteHeaderArr[79] = (byte) (nonce >>> 24); // most significant byte of x
				byteHeaderArr[78] = (byte) (nonce >>> 16);
				byteHeaderArr[77] = (byte) (nonce >>> 8);
				byteHeaderArr[76] = (byte) nonce; // least significant byte of x
				byte[] hashHeader = digest.digest(digest.digest(byteHeaderArr)); // SHA-256 applied twice.

				hashHeaderString = DatatypeConverter.printHexBinary(reverseBlockHeader(hashHeader)); // convert to
																										// hexadecimal
																										// value of the
																										// hashHeader.
				// checking for another nonce such that the first 6 hexadecimal characters of
				// the hash are 0.
				if (hashHeaderString.substring(0, 6).equals("000000")) {
					System.out.println("Hexidecimal value of the nonce: " + Integer.toHexString(nonce));
					System.out.println("Result of the hash: " + hashHeaderString);
					break;
				}
				nonce++;
			}

		} catch (IOException ex) {
			System.out.println(ex.getMessage());
		}

	}

}
