
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.KeySpec;

public class Client {

	private static BigInteger ea, eb;
	private static DataInputStream dis;
	private static DataOutputStream dos;

	private static SecretKey keyAgreement(ObjectInputStream objectIn, ObjectOutputStream objectOut, String userid)
			throws Exception {
		/*
		 * Task 2 Diffie-Hellman protocol
		 */
		final String string1024 = "F488FD584E49DBCD20B49DE49107366B336C380D451D0F7C88B31C7C5B2D8EF6"
				+ "F3C923C043F0A55B188D8EBB558CB85D38D334FD7C175743A31D186CDE33212C"
				+ "B52AFF3CE1B1294018118D7C84A70A72D686C40319C807297ACA950CD9969FAB"
				+ "D00A509B0246D3083D66A45D419F9C7CBD894B221926BAABA25EC355E92F78C7";

		final BigInteger modulus = new BigInteger(string1024, 16); // This is the modulus p

		final BigInteger base1024 = BigInteger.valueOf(2); // The base g which is 2

		/* Generate BigInteger value for A */
		BigInteger a;
		do {
			a = new BigInteger(1024, new Random());
		} while (a.bitLength() < 1024);

		ea = base1024.modPow(a, modulus); // compute e(a), where e(x) = g x mod p.
		objectOut.writeObject(ea); // send result to B (the server).
		eb = (BigInteger) objectIn.readObject(); // Then retrieve the computed result of e(b) from the server.
		// System.out.println("LOOK at EB: " + eb);
		BigInteger key = eb.modPow(a, modulus); // Now A will compute e(b)^a mod p.

		SecretKey secretKey;
		byte[] byteKey = key.toByteArray();// get the byte array representation of the BigInteger key.
		SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede"); // converting it to key material using DESede.
		KeySpec ks = new DESedeKeySpec(byteKey);
		secretKey = skf.generateSecret(ks);

		return secretKey;
	}

	/*
	 * Task 3 - Authenticating Diffie-Hellman Protocol
	 */

	private static boolean verifyServerSignature(SecretKey k, DataInputStream dataIn) {

		try {
			String serverPubKey = "server.pub";
			ObjectInputStream oin = new ObjectInputStream(new FileInputStream(serverPubKey));
			PublicKey publicKey = (PublicKey) oin.readObject();

			// Initialise the cipher
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, k);
			int sigSize = dataIn.readInt(); // read the size of the encrypted server signature.

			byte[] serverSig = new byte[sigSize];
			dataIn.readFully(serverSig);
			// now attempt to decrypt the signature
			serverSig = cipher.doFinal(serverSig);

			// now signature instance is initialised with the server's public key.
			Signature sig = Signature.getInstance("DSA");
			sig.initVerify(publicKey);

			sig.update(eb.toByteArray());
			sig.update(ea.toByteArray());
			return sig.verify(serverSig); // Now attempts to verify the signature.

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return false;
	}

	// Method for sending clients signature to the server along with the BigInteger
	// variables.
	private static void authenticateClient(SecretKey k, DataOutputStream dataOut, String userid) throws Exception {

		String clientPrvKey = userid + ".prv";
		ObjectInputStream objectIn = new ObjectInputStream(new FileInputStream(clientPrvKey));
		ByteBuffer byteBuffer = ByteBuffer.allocate(ea.toByteArray().length + eb.toByteArray().length + 1);
		// Initialise the cipher
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, k);

		PrivateKey privateKey = (PrivateKey) objectIn.readObject(); // read in the client.prv as a private key object.
		Signature sig = Signature.getInstance("DSA");
		sig.initSign(privateKey);

		// initiate signing of the big integer values and the signature.
		byteBuffer.put(ea.toByteArray());
		byteBuffer.put(eb.toByteArray());
		sig.update(byteBuffer);
		byte[] signature = sig.sign();

		// encrypt client signature and send that to the server.
		byte[] encryptedClientSig = cipher.doFinal(signature);

		dataOut.writeInt(encryptedClientSig.length); // write the length
		dataOut.flush();
		dataOut.write(encryptedClientSig);
		dataOut.flush();
	}

	/* Task1 File transmission and encryption */
	private static void recievedContent(SecretKey key, DataInputStream dataIn, String userid) throws Exception {

		try {

			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);
			int dataLength = dataIn.readInt();
			byte[] data = new byte[dataLength];
			dataIn.readFully(data);

			String message = new String(cipher.doFinal(data), "UTF8");

			System.out.println("\nHere is the decrypted content of the text file that belongs to " + userid + "\n"
					+ "message: " + message);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

	}

	public static void main(String[] args) {

		// Check for sufficient arguments are provided.
		if (args.length != 3) {
			throw new IllegalArgumentException("\nInsufficent number of arguments.\n"
					+ "To run this program, you need the 'host', 'port number' and 'userId'");
		}
		// host-name, port-number and user-id are retrieved from the arguments provided
		// in the terminal
		String host = args[0];
		int port = Integer.parseInt(args[1]);
		String userID = args[2];

		System.out.println("Executing Client program...");
		try {

			// establish the connection by specifying the host and port number in the
			// socket.
			Socket s = new Socket(host, port);

			dis = new DataInputStream(s.getInputStream());
			dos = new DataOutputStream(s.getOutputStream());
			ObjectOutputStream oout = new ObjectOutputStream(s.getOutputStream());
			ObjectInputStream oin = new ObjectInputStream(s.getInputStream());
			// Send user id
			dos.writeUTF(userID);
			dos.flush();

			try {

				// get the key
				SecretKey key = keyAgreement(oin, oout, userID);

				recievedContent(key, dis, userID);

				// encrypt client signature and send it to the server.
				authenticateClient(key, dos, userID);
				// if client fails to verify the servers signature then client disconnects from
				// the server.
				// so if this method evaluates to false, the socket will close.
				if (!verifyServerSignature(key, dis)) {
					System.out.println("verification failed!!!");
					System.err.println("The server's signature failed to verify");

					System.exit(-1);

				} else {
					System.out.println("Server Signature is verified!");
				}

			} catch (IOException ioe) {
				ioe.printStackTrace();
			}

		} catch (Exception ex) {
			System.err.println(ex.getMessage());
		}
	}

}
