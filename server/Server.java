
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Server {

	private static BigInteger eb, ea;
	private static DataInputStream dis;
	private static DataOutputStream dos;

	private static SecretKey keyAgreement(ObjectInputStream objectIn, ObjectOutputStream objectOut) throws Exception {
		/*
		 * Task 2 Diffie-Hellman protocol
		 */
		final String string1024 = "F488FD584E49DBCD20B49DE49107366B336C380D451D0F7C88B31C7C5B2D8EF6"
				+ "F3C923C043F0A55B188D8EBB558CB85D38D334FD7C175743A31D186CDE33212C"
				+ "B52AFF3CE1B1294018118D7C84A70A72D686C40319C807297ACA950CD9969FAB"
				+ "D00A509B0246D3083D66A45D419F9C7CBD894B221926BAABA25EC355E92F78C7";

		// String keyString = "dec0de3a5c11696d756e646572636f766572706f6c696365"; old
		// key from part1

		final BigInteger modulus = new BigInteger(string1024, 16); // This is the modulus p

		final BigInteger base1024 = BigInteger.valueOf(2); // The base g which is 2

		/* Generate a random BigInteger value for B */
		BigInteger b;
		do {
			b = new BigInteger(1024, new Random());
		} while (b.bitLength() < 1024);

		eb = base1024.modPow(b, modulus); // compute e(b), where e(x) = g x mod p.
		ea = (BigInteger) objectIn.readObject(); // Then read the computed result of e(a) from the client.
		objectOut.writeObject(eb); // send result to A (the client).
		BigInteger key = ea.modPow(b, modulus); // Now B will compute e(a)^b mod p.

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
	// Stage 1 - B initialises the signature and signs e(a) and e(b)
	private static void authenticateServer(SecretKey k, ObjectOutputStream out, DataOutputStream dataOut)
			throws Exception {
		// Initialise the cipher for encryption
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, k);
		// Initialise Signature
		Signature sig = Signature.getInstance("DSA");
		// Server private key
		String serverPrvKey = "server.prv";
		ObjectInputStream oin = new ObjectInputStream(new FileInputStream(serverPrvKey));

		PrivateKey privateKey = (PrivateKey) oin.readObject(); // read in the server.prv as a private key object.

		sig.initSign(privateKey);

		sig.update(eb.toByteArray());
		sig.update(ea.toByteArray());
		byte[] signature = sig.sign();
		// encrypt signature
		byte[] encryptedSig = cipher.doFinal(signature);

		dataOut.writeInt(encryptedSig.length);
		dataOut.flush();
		dataOut.write(encryptedSig);
		dataOut.flush();

		out.writeObject(eb);
		out.flush();
	}

	// Method for verifying the client signature.
	private static boolean verifyClient(SecretKey k, String userid, DataInputStream dataIn) throws Exception {
		String clientPubKey = userid + ".pub";
		ObjectInputStream oin = new ObjectInputStream(new FileInputStream(clientPubKey));
		ByteBuffer byteBuffer = ByteBuffer.allocate(ea.toByteArray().length + eb.toByteArray().length + 1);

		PublicKey publicKey = (PublicKey) oin.readObject();

		// Initialise the cipher
		Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, k);
		int sigSize = dataIn.readInt(); // read the size of the encrypted server signature.

		byte[] clientSig = new byte[sigSize];
		dataIn.readFully(clientSig);
		// now attempt to decrypt the signature
		clientSig = cipher.doFinal(clientSig);

		// now signature instance is initialised with the server's public key.
		Signature sig = Signature.getInstance("DSA");
		sig.initVerify(publicKey);

		byteBuffer.put(ea.toByteArray());
		byteBuffer.put(eb.toByteArray());
		sig.update(byteBuffer);

		return sig.verify(clientSig); // Now attempts to verify the signature.
	}

	/* Task1 File transmission and encryption */
	private static void sendContent(SecretKey desedeKey, String userid, DataOutputStream dataOut)
			throws IOException, InvalidKeyException {

		String str = null;
		String fileName = userid + ".txt";

		byte[] resultTemp = null;
		byte[] result = null;
		try {
			str = new String(Files.readAllBytes(Paths.get(fileName)));

			// get bytes of the content
			resultTemp = str.getBytes("UTF8");

			// Initialise the cipher for encryption
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, desedeKey);

			// then encrypt the file
			result = cipher.doFinal(resultTemp);

			// write the file to the client.
			dataOut.writeInt(result.length);
			dataOut.flush();
			dataOut.write(result);
			dataOut.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws Exception {

		if (args.length != 1) {
			System.err.println("Enter the port number");
			System.exit(-1);
		}

		int port = Integer.parseInt(args[0]);
		ServerSocket ss = new ServerSocket(port);
		System.out.println("Waiting incoming connection...");
		boolean serverFlag = false;

		while (true) {
			Socket clientSockets = ss.accept();
			dos = new DataOutputStream(clientSockets.getOutputStream());
			dis = new DataInputStream(clientSockets.getInputStream());
			ObjectInputStream objectInputStream = new ObjectInputStream(clientSockets.getInputStream());
			ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSockets.getOutputStream());

			String receivedUserID = dis.readUTF(); // read un-encrypted ID sent from the client.
			System.out.println(receivedUserID);

			try {
				SecretKey key = keyAgreement(objectInputStream, objectOutputStream); // get secret key for encryption.

				sendContent(key, receivedUserID, dos); // then send encrypted result to client

				// check if the client is verified
				if (!verifyClient(key, receivedUserID, dis)) {
					System.err.println("cannot authenticate client");
					System.out.println("Sorry client is not authenticated...");
					clientSockets.close();
					continue;
				} else {
					System.out.println("Client is authenticated");
				}

				// Get the server signature, encrypt it and send to the client.
				authenticateServer(key, objectOutputStream, dos);

			} catch (EOFException ex) {
				ex.printStackTrace();
				System.err.println("client disconnected.");
				continue;
			}

		}

	}

}
