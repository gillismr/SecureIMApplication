import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SIMClient{

	//Fields for server connection configuration
	Scanner sc;
	String serverIP;
	int serverPort;
	Socket server;
	
	//Server public key fields
	byte[] serverKeyBytes;
	KeyFactory rsaKeyFactory;
	X509EncodedKeySpec publicSpec;
	PublicKey serverKey;
	
	//Streams between this client and the server
	DataInputStream input;
	DataOutputStream output;
    
    //Login
    BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
    String name, password;
    
    //Credentials to server
    byte[] nonce1 = new byte[16]; // 16 bytes = 128 bits
    byte[] pwHash;
    byte[] sendData;
    byte[] encryptedSendData;
    
    //Cookie
    byte[] cookie;
    
    //The person we're talking to
    boolean talking;
    InetAddress recipientINA;
	String recipient;
    PrivateKey signatureKey;
	PublicKey verificationKey;
	byte[] ticketToB;
	
	//Connecting to them
	private Socket recipientSocket;
	private ServerSocket listening;
	DataInputStream inputB;
	DataOutputStream outputB;
	
	//DiffieHellman stuff
	BigInteger p = new BigInteger("105721529231725396278744238019721944883459258934172331899960783719893356089817034253461201515439737670361933937940217427577693473956344804895358846880822392696046488918274717636071583814523522759796204222618840365316653936434709172113382318497752088322889563530999616413642023504696663722814258660783284649709");
	BigInteger g = new BigInteger("62951193033649707239238510868644285309198569779488005138430533330591756100547054332779476210740737931462466271496214673336150099168994589303046765366535435267910408582532215038620252157609127503823477022010406010833479619195676348865393025560501628436016618301150440981638807075483419386887089022419473465714");
	int l = 1023;
	SecretKey perfectSecretKey;
	
	//For logout
	boolean logout;
	
	public SIMClient(){
		
		recipient = null;
		logout = false;
		
		//Get configuration info, set up connection(socket) with server
    	connectToServer();
    	
    	//Get the server's public key
    	setServerKey();
    	
    	//Establish the I/O streams
    	setServerStreams();
    	
    	//Gather login info from user
    	setLoginInfo();
    	
    	//Prepare and send credentials to server (generate nonce, hash PW, encrypt with serverKey)
    	sendCredentials();
    	
    	//Echo the received cookie
    	echoCookie();
    	
    	//Talk to server, make sure we're logged in and good to go
    	serverWelcome();
    	
    	processCommand();
    	
    	
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException {
    	
		@SuppressWarnings("unused")
		SIMClient thisClient = new SIMClient();
		
    }
	
	private void connectToServer(){
		try {
			sc = new Scanner(new File("config.txt"));
			serverIP = sc.next();
			serverPort = Integer.parseInt(sc.next());
			server = new Socket(serverIP, serverPort);}
		catch (Exception e) {
			System.out.println(e);}
		System.out.println("Server config info found, connection established.");
	}
	
	private void setServerKey(){
		try {
			serverKeyBytes = readByteFromFile(new File("pub1.class"));
			rsaKeyFactory = KeyFactory.getInstance("RSA");
			publicSpec = new X509EncodedKeySpec(serverKeyBytes);
			serverKey = rsaKeyFactory.generatePublic(publicSpec);}
		catch (Exception e) {
			System.out.println(e);}
		//System.out.println("Server public key found and imported.");
	}
	
	private void setServerStreams(){
		try {
			output = new DataOutputStream(server.getOutputStream());
			output.flush();
			input = new DataInputStream(server.getInputStream());}
    	catch (Exception e){
    		System.out.println(e);}
		//System.out.println("Server streams established.");
	}
	
	private void setLoginInfo(){
		try {
    		System.out.print("LOGIN NAME: ");
    		name = stdin.readLine();
    		System.out.print("PASSWORD: ");
    		password = stdin.readLine();
		} catch (Exception e) {
			System.out.println(e);}
	}
	
	private void writeMessage(DataOutputStream dout, byte[] msg) throws IOException {
		int length = msg.length;
		dout.writeInt(length);
		dout.write(msg, 0, length);
		dout.flush();
	}

	public byte[] readMessage(DataInputStream din) throws IOException {
		int length = din.readInt();
		byte[] msg = new byte[length];
		din.readFully(msg);
		return msg;
	}
	
	private void sendCredentials(){
		try{
			Random rng = new SecureRandom();
			rng.nextBytes(nonce1); // 16 bytes = 128 bits
			//System.out.println("Nonce chosen.");
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			pwHash = md.digest(password.getBytes()); // 64 bytes = 512 bits
			//System.out.println("Password hashed.");
			sendData = makeLoginCreds(nonce1, pwHash, name);
	    	//System.out.println("Send data prepared.");
	    	Cipher publicChiper = Cipher.getInstance("RSA");
			publicChiper.init(Cipher.ENCRYPT_MODE, serverKey);
			encryptedSendData = publicChiper.doFinal(sendData);
			//System.out.println("Send data encrypted.");
			writeMessage(output, encryptedSendData);
			//System.out.println("Credentials sent.");
		}
		catch (Exception e){
			System.out.println(e);}
	}
		
	private byte[] makeLoginCreds(byte[] nonce, byte[] hash, String name) throws IOException{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(nonce);
		outputStream.write(hash);
		outputStream.write(name.getBytes());
		return outputStream.toByteArray();
	}
	
	private void echoCookie(){
		try {
			cookie = readMessage(input);
			writeMessage(output, cookie);
			//System.out.println("Cookie received and returned.");
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
	
	private void serverWelcome(){
		try{
			System.out.println(new String(readMessage(input)));
			talking = false;
			listening = new ServerSocket(serverPort +1);
			new acceptConnection().start();
		}
		catch (Exception e){
			System.out.println(e);
		}
	}
	
	private void processCommand(){
		try{
			
			System.out.println("Type 'list' for a list of available users.");
			System.out.println("Type 'send <USER> <MESSAGE>' to send that user a message.");
			System.out.println("Type 'logout' to logout. (THIS DOESN'T WORK)");
			
			while(true){
						
				String command = stdin.readLine();
				
				if(command.equalsIgnoreCase("list")){
					writeMessage(output, "list".getBytes());
					System.out.println(new String(readMessage(input)));
				}
				else if(command.startsWith("send ")){
					doSend(command.substring(5));
				}
				else if(command.equalsIgnoreCase("logout")){
					System.out.println("Logging you out, come back soon!\n");
					writeMessage(output, "logout".getBytes());
					logout = true;
					dcFromServer();
					dcFromB();
					return;
				}
				else{
					System.out.println("Bad input, try again.\n");
					System.out.println("Type 'list' for a list of available users.");
					System.out.println("Type 'send <USER> <MESSAGE>' to send that user a message.");
					System.out.println("Type 'logout' to logout. (THIS DOESN'T WORK)");
				}
			}
		}catch (Exception e){
			System.out.println(e);
		}
	}
	
	private void doSend(String nameAndMsg){
		int endNameIndex = nameAndMsg.indexOf(" ");
		String newRecipient = nameAndMsg.substring(0, endNameIndex);
		String message = nameAndMsg.substring(endNameIndex + 1);
		
		if(newRecipient.equals(recipient)){
			//System.out.println("Still talking to " + recipient + ", assuming SecretKey is already in place.");
			talkToB(message);
			return;
		}
		
		try{
			
			//System.out.println("Requesting credentials to talk to " + newRecipient + " from the server.");
			//Ask the server for the info to set up a connection & secretKey with the user whose name we entered
			writeMessage(output, ("connect " + newRecipient).getBytes());
			String maybeFound = new String(readMessage(input));
			if(maybeFound.equals("none")){
				System.out.println("No such user, try again.");
				return;
			}
			
			//Set the recipient's name and get their InetAddress from the server
			talking = true;
			recipient = newRecipient;
			recipientINA = InetAddress.getByAddress(readMessage(input));
			
			//Get the package of materials from the server; our encrypted RSA info, the nonce, the ticket to B, and the signature
			byte[] forA = readMessage(input);
			byte[] nonce1Check = readMessage(input);
			ticketToB = readMessage(input);
			byte[] signature = readMessage(input);
			//System.out.println("Received the package from the server.");
			
			//Set up the verification of the signature
			Signature sig = Signature.getInstance("SHA512withRSA");
			sig.initVerify(serverKey);
			sig.update(forA);
			sig.update(nonce1Check);
			sig.update(ticketToB);
			
			// Verify the signature of the final message from the server
			if(!sig.verify(signature)){
				System.out.println("Signature verification failed.");
				return;
			}
			
			//Check that the nonce is what it should be
			if(!Arrays.equals(nonce1, nonce1Check)){
				System.out.println("The nonce was different.");
				return;
			}
			
			//System.out.println("Signature and nonce verified.");
			
			//Get our password hash ready to use as a bootstrapped AES key
			byte[] keyOfA = Arrays.copyOf(pwHash, 16); // use only first 128 bit
			
			//Decrypt our half of the RSA package
			SecretKeySpec secretKeySpecA = new SecretKeySpec(keyOfA, "AES");
			Cipher secCipher = Cipher.getInstance("AES");
			secCipher.init(Cipher.DECRYPT_MODE, secretKeySpecA);
			byte[] ourDecryptedPart = secCipher.doFinal(forA);
			//System.out.println("Decrypted our part of the package.");
			
			//Break the decrypted RSA package into its parts
			int privateKeyLength = ByteBuffer.wrap(Arrays.copyOfRange(ourDecryptedPart, 0, 4)).getInt();
			int publicKeyLength = ByteBuffer.wrap(Arrays.copyOfRange(ourDecryptedPart, 4, 8)).getInt();
					
			byte[] signatureKeyBytes = Arrays.copyOfRange(ourDecryptedPart, 8, 8 + privateKeyLength);
			byte[] verifyKeyBytes = Arrays.copyOfRange(ourDecryptedPart, 8 + privateKeyLength, 8 + privateKeyLength + publicKeyLength);
			byte[] otherNameBytes = Arrays.copyOfRange(ourDecryptedPart, 8 + privateKeyLength + publicKeyLength, ourDecryptedPart.length);
			String nameToCheck = new String(otherNameBytes);
			//System.out.println(nameToCheck);
			//Check that the name matches
			if(!nameToCheck.equals(recipient)){
				System.out.println("These are credentials for the wrong person!");
				return;
			}
			//System.out.println("Credentials are for the right recipient, converting our Sig/Ver key from the byte[]s");
			
			//Convert the RSA key byte[]s to RSA keys for signature and verification of the DH exchange
			KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(signatureKeyBytes);
			X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(verifyKeyBytes);
			signatureKey = rsaKeyFactory.generatePrivate(privateSpec);
			verificationKey = rsaKeyFactory.generatePublic(publicSpec);
			
			//Prepare to communicate with B
			connectToB();
			
			System.out.println("Beginning Diffie-Hellman exchange to establish perfectSecretKey");
			//Complete a signed DH exchange with B to create the perfectSecretKey
			establishDHAsA();
			
			//Start listening to their encrypted messages
			new ListenToB().start();
			
			//Actually send the message
			talkToB(message);
			
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
	
	private void connectToB(){
		try {
			System.out.println("Attempting to connect to " + recipient + ".");
			recipientSocket = new Socket(recipientINA, serverPort + 1);
			outputB = new DataOutputStream(recipientSocket.getOutputStream());
			outputB.flush();
			inputB = new DataInputStream(recipientSocket.getInputStream());
			writeMessage(outputB, name.getBytes());
			System.out.println("Connected to " + recipient + ", streams set up.");
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	
	//A Thread extension for receiving messages from the user we're connected to 
	class ListenToB extends Thread {
		public void run() {
			while(!logout) {
				try {
					String msg = new String(readMessage(inputB));
					System.out.println(recipient + ": " + msg);

				} catch(Exception e) {
					System.out.println(e);
				}
			}
		}
	}

	//A Thread extension for receiving messages from the user we're connected to 
	class acceptConnection extends Thread {
		public void run() {
			while(!talking && !logout) {
				try {
					recipientSocket = listening.accept();
					recipientINA = recipientSocket.getInetAddress();
					outputB = new DataOutputStream(recipientSocket.getOutputStream());
					outputB.flush();
					inputB = new DataInputStream(recipientSocket.getInputStream());
					recipient = new String(readMessage(inputB));
					System.out.println("Connected to " + recipient + ", streams set up.");
					System.out.println("Beginning Diffie-Hellman exchange to establish perfectSecretKey");
					
					//Complete a signed DH exchange with B to create the perfectSecretKey
					establishDHAsB();
					talking = true;
					//Start listening to their encrypted messages
					new ListenToB().start();
				} catch(Exception e) {
					System.out.println(e);
				}
			}
		}
	}

	private void talkToB(String message){
		try {

			writeMessage(outputB, message.getBytes());

		} catch (IOException e) {
			System.out.println(e);
		}
	}
	
	private void dcFromServer(){
		try{
			input.close();
			output.close();
			server.close();}
		catch(Exception e){
			System.out.println(e);
		}
	}
	/*
	private void forgetRecipient(){
		recipient = null;
		signatureKey = null;
		verificationKey = null;
	}
	*/
	private void dcFromB(){
		try{
			inputB.close();
			outputB.close();
			recipientSocket.close();
			
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
	/*
	private void dcFromA(){
		try{
			inputB.close();
			outputB.close();
			recipientSocket.close();
			
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
	*/
	private void establishDHAsA(){
		try {
			
			//Send B their ticket
			writeMessage(outputB, ticketToB);
						
			//Receive a cookie from B
			byte[] cookieB = readMessage(inputB);
			
			//Prepare our half of the DH exchange
			//Use the hard-coded values to generate our DH key Classes: the internal and external halves of our half of the DH exchange
		    KeyPairGenerator dhKeyGen = KeyPairGenerator.getInstance("DH");
		    DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
		    dhKeyGen.initialize(dhSpec);
		    KeyPair dhKeyPair = dhKeyGen.generateKeyPair();

		    // Get the generated public and private keys
		    PrivateKey dhPrivateKeyA = dhKeyPair.getPrivate();
		    PublicKey dhPublicKeyA = dhKeyPair.getPublic();

		    //Prepare our DH contribution for sending it to B
		    byte[] dhPublicKeyBytesA = dhPublicKeyA.getEncoded();
		    
		    //Sign our half of the DH exchange and the other info
		    Signature signMyDH = Signature.getInstance("SHA512withRSA");
		    signMyDH.initSign(signatureKey);
		    signMyDH.update(name.getBytes());
		    signMyDH.update(dhPublicKeyBytesA);
			byte[] signature = signMyDH.sign();
		    
			//Send B the cookie and our half of the DH exchange, signed of course
			writeMessage(outputB, cookieB);
			writeMessage(outputB, name.getBytes());
			writeMessage(outputB, dhPublicKeyBytesA);
			writeMessage(outputB, signature);
						
		    //Retrieve the name, public key, and signature bytes from B
			byte[] checkNameBytes = readMessage(inputB);
			byte[] publicKeyBytesB = readMessage(inputB);
			byte[] signatureB = readMessage(inputB);
			String checkName = new String(checkNameBytes);
			
			//Prep the signature for verification
			Signature verifyHisDH = Signature.getInstance("SHA512withRSA");
			verifyHisDH.initVerify(verificationKey);
			verifyHisDH.update(checkNameBytes);
			verifyHisDH.update(publicKeyBytesB);
						
			// Verify the signature of the above data
			if(!verifyHisDH.verify(signatureB)){
				System.out.println("Signature verification failed.");
				return;
			}
			//Verify the name
			if(!checkName.equals(recipient)){
				System.out.println("This is a key for the wrong person!");
				return;
			}
			
			// Calculate Kab, the shared, perfect secret key
		    // Convert the public key bytes into a PublicKey object
		    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytesB);
		    KeyFactory keyFact = KeyFactory.getInstance("DH");
		    PublicKey dhPublicKeyB = keyFact.generatePublic(x509KeySpec);

		    // Prepare to generate the secret key with the our private half of the DH key and B's public part of it
		    KeyAgreement ka = KeyAgreement.getInstance("DH");
		    ka.init(dhPrivateKeyA);
		    ka.doPhase(dhPublicKeyB, true);

		    // Generate the secret key
		    perfectSecretKey = ka.generateSecret("DES");
		    
		    //Hash the psKey and send it to B
		    MessageDigest md = MessageDigest.getInstance("SHA-512");
		    writeMessage(outputB, md.digest(perfectSecretKey.getEncoded()));
		    			
		    //Receive the hash of 1 concatenated with the psKey from B
		    byte[] keyHashToCheck = readMessage(inputB);
			
		    //Compute hash(1|psKey) ourselves
			byte[] oneByte = new byte[1];
			oneByte[0] = 1;
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write(oneByte);
			outputStream.write(perfectSecretKey.getEncoded());
			byte[] keyBytesPlus1 = outputStream.toByteArray();
			byte[] keyHashPlus1 = md.digest(keyBytesPlus1);
			
			//Check that it matches what B sent us
			if(!Arrays.equals(keyHashToCheck, keyHashPlus1)){
				System.out.println("Hash check failed, perfectSecretKey mismatch?");
				return;
			}
			
			//ALRIGHT, we're ready to talk!
			System.out.println("Secret key established for talking to " + recipient + ", sending message.");
			
			
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	private void establishDHAsB(){
		try {
			
			//Receive our ticket from A
			byte[] myTicket = readMessage(inputB);
			
			//Decrypt the ticket into its byte[]
			byte[] keyOfB = Arrays.copyOf(pwHash, 16); // use only first 128 bit
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyOfB, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] decryptedTicket = cipher.doFinal(myTicket);
			
			//Break the decrypted RSA package into its parts
			int privateKeyLength = ByteBuffer.wrap(Arrays.copyOfRange(decryptedTicket, 0, 4)).getInt();
			int publicKeyLength = ByteBuffer.wrap(Arrays.copyOfRange(decryptedTicket, 4, 8)).getInt();
					
			byte[] signatureKeyBytes = Arrays.copyOfRange(decryptedTicket, 8, 8 + privateKeyLength);
			byte[] verifyKeyBytes = Arrays.copyOfRange(decryptedTicket, 8 + privateKeyLength, 8 + privateKeyLength + publicKeyLength);
			byte[] otherNameBytes = Arrays.copyOfRange(decryptedTicket, 8 + privateKeyLength + publicKeyLength, decryptedTicket.length);
			String nameToCheck = new String(otherNameBytes);
			
			//Check that it's for the initiating person
			if(!nameToCheck.equals(recipient)){
				System.out.println("These are credentials for the wrong person!");
				return;
			}
			
			//Convert the keyByte[]s into the RSA keys for the DH exchange
			KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(signatureKeyBytes);
			X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(verifyKeyBytes);
			signatureKey = rsaKeyFactory.generatePrivate(privateSpec);
			verificationKey = rsaKeyFactory.generatePublic(publicSpec);
			
			//Make a nonce for the cookie
			Random rng = new SecureRandom();
			byte[] nonce2 = new byte[16];
			rng.nextBytes(nonce2); // 16 bytes = 128 bits
			
			//Get the IP for the cookie
			byte[] ipOfA = recipientSocket.getInetAddress().getAddress();
			
			
			//Make the cookie, hash it, send it
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write(ipOfA);
			outputStream.write(nonce2);
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			byte[] cookieForA = md.digest(outputStream.toByteArray());
			writeMessage(outputB, cookieForA);
						

			//Get the next set of input from A
			byte[] cookieToCheck = readMessage(inputB);
			byte[] nameBytesOfA = readMessage(inputB);
			byte[] dhPublicKeyBytesA = readMessage(inputB);
			byte[] signatureOfA = readMessage(inputB);
			String checkName = new String(nameBytesOfA);
						
			//Check the cookie
			if(!Arrays.equals(cookieToCheck, cookieForA)){
				System.out.println("Cookie check failed.");
			}
			
			//Set up the signature verification of the DH exchange
			Signature verifyHisDH = Signature.getInstance("SHA512withRSA");
			verifyHisDH.initVerify(verificationKey);
			verifyHisDH.update(nameBytesOfA);
			verifyHisDH.update(dhPublicKeyBytesA);
						
			//Verify the signature of the DH exchange
			if(!verifyHisDH.verify(signatureOfA)){
				System.out.println("Signature verification failed.");
				return;
			}
			
			//Check that the name in the signed DH exchange matches the initiating user 
			if(!checkName.equals(recipient)){
				System.out.println("This is a key for the wrong person!");
				return;
			}
			
			// Complete all DiffieHellman calculations
			// Use the hard-coded values to generate a key pair
		    KeyPairGenerator dhKeyGen = KeyPairGenerator.getInstance("DH");
		    DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
		    dhKeyGen.initialize(dhSpec);
		    KeyPair dhKeyPair = dhKeyGen.generateKeyPair();

		    // Get the generated public and private keys
		    PrivateKey dhPrivateKeyB = dhKeyPair.getPrivate();
		    PublicKey dhPublicKeyB = dhKeyPair.getPublic();

		    // Convert the bytes of A's public key back to a PublicKey object
		    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(dhPublicKeyBytesA);
		    KeyFactory keyFact = KeyFactory.getInstance("DH");
		    PublicKey dhPublicKeyA = keyFact.generatePublic(x509KeySpec);

		    // Prepare to generate the secret key with our private key and public key of the other party
		    KeyAgreement ka = KeyAgreement.getInstance("DH");
		    ka.init(dhPrivateKeyB);
		    ka.doPhase(dhPublicKeyA, true);

		    // Generate the secret key
		    perfectSecretKey = ka.generateSecret("DES");
			
		    
		    //Sign our half of the DH exchange
		    Signature signMyDH = Signature.getInstance("SHA512withRSA");
		    signMyDH.initSign(signatureKey);
		    signMyDH.update(name.getBytes());
		    signMyDH.update(dhPublicKeyB.getEncoded());
			byte[] signature = signMyDH.sign();
		    
		    //Resume communication with A, send them our part of the signed DH exchange
			writeMessage(outputB, name.getBytes());
			writeMessage(outputB, dhPublicKeyB.getEncoded());
		    writeMessage(outputB, signature);
		  
		    
		    //Receive the hash of the perfectSecretKey from A 
		    byte[] keyHashToCheck = readMessage(inputB);
		    
		    //Hash our copy of the psKey 
		    byte[] keyHash = md.digest(perfectSecretKey.getEncoded());  
		    
		    //Check that the hashes match
		    if(!Arrays.equals(keyHashToCheck, keyHash)){
				System.out.println("Hash check failed, perfectSecretKey mismatch?");
				return;
			}
			
		    //Compute the hash of 1 concatenated with the psKey
			byte[] oneByte = new byte[1];
			oneByte[0] = 1;
			outputStream = new ByteArrayOutputStream( );
			outputStream.write(oneByte);
			outputStream.write(perfectSecretKey.getEncoded());
			byte[] keyBytesPlus1 = outputStream.toByteArray();
			byte[] keyHashPlus1 = md.digest(keyBytesPlus1);
			
			//Send hash+1 to A
			writeMessage(outputB, keyHashPlus1);
						
			System.out.println("Beginning chat session with " + recipient + ". You can now send and receive messages with them.");
			
			//Then we should receive their message and be able to send them our own...
		
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	
	
	// read bytes from a file
	public static byte[] readByteFromFile(File f) throws Exception {
		if (f.length() > Integer.MAX_VALUE)
			System.out.println("File is too large");
		
		byte[] buffer = new byte[(int) f.length()];
		InputStream fis = new FileInputStream(f);;
		DataInputStream dis = new DataInputStream(fis);
		dis.readFully(buffer);
		dis.close();
		fis.close();
		
		return buffer;
	}
		

	
	
	

}
