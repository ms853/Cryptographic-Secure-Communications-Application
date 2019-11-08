/* This program generates a pair of matching public/private DSA keys.
 * It takes a userid as an argument, and places the generated keys in
 * "<userid>.pub" and "<userid>.prv" in the current working directory.
 * It is up to you to put the generated keys at some appropriate   
 * location for testing.
 *
 * This file does not contain any code that you need to include in
 * your own program, and is not part of the handin. 
 */

import java.io.*;
import java.security.*;

public class DSAKeyGen {

    public static void main(String [] args) throws Exception {

	if (args.length < 1) {
	    System.err.println("Usage: java DSAKeyGen userid");
	    System.exit(-1);
	}

	KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
	kpg.initialize(1024);
	KeyPair kp = kpg.genKeyPair();

	ObjectOutputStream objOut = new ObjectOutputStream(new FileOutputStream(args[0] + ".pub"));
	objOut.writeObject(kp.getPublic());
	objOut.close();

	objOut = new ObjectOutputStream(new FileOutputStream(args[0] + ".prv"));
	objOut.writeObject(kp.getPrivate());

    }

}
