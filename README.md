# Cryptographic-Secure-Communications-Application
Console-based secure communications application implemented in Java. 

Firstly, I developed a client-server system for encrypted file transmission. The file transmission however, relied on symmetric key cryptography. So this means only one key is used to en/decrypt the message that is sent from client to server. 

Then I implemented a public key cryptographic system to form as a basis for authentication both parties before the communication begins. So the program I implemented now uses a dynamically generated key based on the Diffie-Hellman protocol.


## The use of Diffie Hellman Protocol in authentication 
At the end of the protocol, in addition to sharing a secret key K, both A and B can be sure of the other’s identity.
So the way I implemented the protocol for authentication between the two parties can be seen by the following protocol narration: 

1. A → B: e(a)
2. B → A: e(b)
3. B → A: {{e(b), e(a)} B − } K
4. A → B: {{e(a), e(b)} A − } K

This is the step by step explanation:

• Steps 1 and 2 are identical to Task 2, where A and B exchange their e(a) and e(b). After
Step 2, both A and B can compute the key K.

• B then signs the pair of integers e(b), e(a) with his private key. (See below for signatures
and keys.) This signature is then encrypted with DESede with key K, in ECB mode.
Finally, B sends the value e(b) and the encrypted signature to A.

• A then attempts to decrypt the encrypted signature, and verify the signature with B’s
public key. If the decryption fails, or the signature does not verify, A terminates the
program.

• Otherwise, A signs the pair of integers e(a), e(b) with her private key. This signature is
then encrypted with DESede with key K, in ECB mode. A sends this encrypted signature
to B.

• Finally, when B received the above, he attempts to decrypt the encrypted signature,
and verify the signature. Again B should terminate the connection if the decryption or
signature verification fails.

I achieved the implementation of the protocol above through the use of Signatures and keys. The signatures are file names generated by the DSAKeyGeneration.java class. So for e.g. <userid>.pub (for the public keys) and <userid>.prv (for private keys).
  
## Bitcoin Blocks Computation
This is a separate task, whereby I had to write a java program that computes the first 80 bytes (160 Hexidecimal Characters) of the bitcoin header.
You can find block.txt which is the corresponding textfile I had to read the data from and compute the bitcoin hash.
SHA-256 is the hash algorithm I used to has the the data. 

### Aim of the program
The last 4 bytes of the header store the value of a nonce. The mining process is about
finding a value of this nonce so that the block hash is below a certain value. I did an easier version of the mining process, by finding another nonce (different from the one
already in the block header) so that the first 24 bits (6 hex chars) of the resulting hash are 0.
