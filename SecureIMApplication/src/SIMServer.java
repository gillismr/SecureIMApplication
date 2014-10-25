import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


/*
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.io.*;
 */


public class SIMServer {

	public static void main(String[] args) throws IOException, GeneralSecurityException {

		@SuppressWarnings("resource")
		ServerSocket serverSocket = new ServerSocket(9090);
		System.out.println("Socket established");
		byte[] privateKeyBytes = readByteFromFile(new File("priv1.class"));

		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey privateKey = rsaKeyFactory.generatePrivate(privateSpec);

		Random rng = new SecureRandom();
		byte[] cookieNonce = new byte[16]; // 16 bytes = 128 bits
		rng.nextBytes(cookieNonce);

		while(true){
			Socket clientSocket = serverSocket.accept();
			System.out.println("Socket established with someone at" + clientSocket.getInetAddress().toString());
			ClientThread c = new ClientThread(clientSocket, privateKey, cookieNonce);
			c.start();
		}

	}

	// read bytes from a file
	public static byte[] readByteFromFile(File f) throws IOException{
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

class ClientEntry{

	public String name;
	public byte[] pwHash;
	public InetAddress ip;
	public boolean available;
	
	//Added as per presentation feedback?
	public int listeningSocketPort;

	public ClientEntry(String name, byte[] pwHash, InetAddress ip, int port, boolean available){
		this.name = name;
		this.pwHash = pwHash;
		this.ip = ip;
		this.listeningSocketPort = port;
		this.available = available;
	}

	public void setIP(InetAddress newIP){
		this.ip = newIP;
	}

	public void setAvailable(boolean available){
		this.available = available;
	}
}



class ClientThread extends Thread {

	private DataInputStream input = null;
	private DataOutputStream output = null;
	private Socket clientSocket = null;
	private PrivateKey privateKey;
	private byte[] cookieNonce;
	private byte[] nonce1, pwHash, nameBytes;
	private int clientIndex;
	private ClientEntry clientEntry;
	//private InetAddress ip;
	String name;
	String otherName;
	ClientEntry otherUser;

	private static final List<ClientEntry> clients = new ArrayList<ClientEntry>();

	public ClientThread(Socket clientSocket, PrivateKey privateKey, byte[] cookieNonce) throws IOException, NoSuchAlgorithmException {
		this.clientSocket = clientSocket;
		this.input = new DataInputStream(clientSocket.getInputStream());
		this.output = new DataOutputStream(clientSocket.getOutputStream());
		output.flush();
		this.privateKey = privateKey;
		this.cookieNonce = cookieNonce;
	}

	public void run() {
		byte[] initialCreds;
		try {
			System.out.println("Thread started. Waiting for login credentials.");
			initialCreds = readMessage();
			System.out.println("Initial credentials received, sending cookie.");
			writeMessage(makeCookie());

			System.out.println("Cookie sent, awaiting response.");
			byte[] echoedCookie = readMessage(); 
			if(!checkCookie(echoedCookie)){
				System.out.println("Cookie mismatch.");
				disconnect();
				return;
			}


			System.out.println("Cookie received, IP address verified. Decrypting initial credentials.");
			Cipher privateCipher = Cipher.getInstance("RSA");
			privateCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedCreds = privateCipher.doFinal(initialCreds);

			System.out.println("Credentials decrypted. Seperating peices.");
			nonce1 = Arrays.copyOfRange(decryptedCreds, 0, 16);
			pwHash = Arrays.copyOfRange(decryptedCreds, 16, 80);
			nameBytes = Arrays.copyOfRange(decryptedCreds, 80, decryptedCreds.length);
			name = new String(nameBytes);

			System.out.println("Credentials separated for user " + name + ". Checking login history...");
			clientIndex = getClientIndex(name);

			if(clientIndex == -1){
				System.out.println("New user detected, creating new client entry.");
				
				//May have to change to clientSocket.getLOCALPort()
				clientEntry = new ClientEntry(name, pwHash, clientSocket.getInetAddress(), clientSocket.getPort(), true);
				clients.add(clientEntry);
				clientIndex = clients.indexOf(clientEntry);
				System.out.println(name + " listed as client #" + clientIndex);
			}
			else if (correctPassword()){
				System.out.println("Password verified. Updating IP address and availability for this session.");
				clients.get(clientIndex).setIP(clientSocket.getInetAddress());
				clients.get(clientIndex).setAvailable(true);
			}
			else{
				System.out.println("Incorrect PW, terminating session.");
				writeMessage("Incorrect PW, terminating session.".getBytes());

				disconnect();
				return;
			}

			writeMessage(("Welcome, " + name + ".\n").getBytes());

			processCommand();


		} 
		catch (Exception e) {
		}
	}

	private void writeMessage(byte[] msg) throws IOException {
		int length = msg.length;
		output.writeInt(length);
		output.write(msg, 0, length);
		output.flush();
	}

	public byte[] readMessage() throws IOException {
		int msgLen = input.readInt();
		byte[] msg = new byte[msgLen];
		input.readFully(msg);
		return msg;
	}

	private void processCommand(){
		while(!clientSocket.isClosed()){
			try{
				String command = new String(readMessage());
				if(command.equalsIgnoreCase("list")){
					writeMessage(listClients());

				}
				else if(command.startsWith("connect ")){
					startPreparingKeyPair(command.substring(8));
				}
				else if(command.equalsIgnoreCase("logout")){
					clients.get(clientIndex).setAvailable(false);
					disconnect();
					return;
				}
				else{
					writeMessage("Bad input, try again.\n".getBytes());

				}
			}
			catch(Exception e){
				System.out.println(e);
			}
		}
	}

	private void startPreparingKeyPair(String maybeName){
		try{
			System.out.println("Looking for client \"" + maybeName + "\" in the list of clients." );
			
			int otherIndex = getClientIndex(maybeName);
			System.out.println("Client found at index " + otherIndex);
			
			if(otherIndex == -1 || !clients.get(otherIndex).available){
				writeMessage("none".getBytes());
				return;
			}
			writeMessage("found".getBytes());
			otherUser = clients.get(otherIndex);
			otherName = maybeName;
			writeMessage(otherUser.ip.getAddress());
			sendKeyPairPackage();

		}
		catch(Exception e){
			System.out.println(e);
		}
	}

	private void sendKeyPairPackage(){
		try{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keyPairForA = keyGen.genKeyPair();
			KeyPair keyPairForB = keyGen.genKeyPair();
			PrivateKey privateA = keyPairForA.getPrivate();
			PublicKey publicA = keyPairForA.getPublic();
			PrivateKey privateB = keyPairForB.getPrivate();
			PublicKey publicB = keyPairForB.getPublic();
			
			byte[] publicBBytes = publicB.getEncoded();
			byte[] privateABytes = privateA.getEncoded();
			byte[] privateBBytes = privateB.getEncoded();
			byte[] publicABytes = publicA.getEncoded();
			
			byte[] forAprivALength = ByteBuffer.allocate(4).putInt(privateABytes.length).array();
			byte[] forApubBLength = ByteBuffer.allocate(4).putInt(publicBBytes.length).array();
			byte[] forBprivBLength = ByteBuffer.allocate(4).putInt(privateBBytes.length).array();
			byte[] forBpubALength = ByteBuffer.allocate(4).putInt(publicABytes.length).array();
			
			byte[] keyOfA = Arrays.copyOf(pwHash, 16); // use only first 128 bit
			byte[] keyOfB = Arrays.copyOf(otherUser.pwHash, 16); // use only first 128 bit

			SecretKeySpec secretKeySpecA = new SecretKeySpec(keyOfA, "AES");
			SecretKeySpec secretKeySpecB = new SecretKeySpec(keyOfB, "AES");

			Cipher cipherA = Cipher.getInstance("AES");
			Cipher cipherB = Cipher.getInstance("AES");
			cipherA.init(Cipher.ENCRYPT_MODE, secretKeySpecA);
			cipherB.init(Cipher.ENCRYPT_MODE, secretKeySpecB);

			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write(forAprivALength);
			outputStream.write(forApubBLength);
			outputStream.write(privateA.getEncoded());
			outputStream.write(publicB.getEncoded());
			outputStream.write(otherName.getBytes());
			byte[] forA = cipherA.doFinal(outputStream.toByteArray());

			outputStream = new ByteArrayOutputStream( );
			outputStream.write(forBprivBLength);
			outputStream.write(forBpubALength);
			outputStream.write(privateB.getEncoded());
			outputStream.write(publicA.getEncoded());
			outputStream.write(name.getBytes());
			byte[] forB = cipherB.doFinal(outputStream.toByteArray());

			Signature sig = Signature.getInstance("SHA512withRSA");
			sig.initSign(privateKey);
			sig.update(forA);
			sig.update(nonce1);
			sig.update(forB);
			byte[] signature = sig.sign();

			writeMessage(forA);
			writeMessage(nonce1);
			writeMessage(forB);
			writeMessage(signature);

		}
		catch(Exception e){
			System.out.println(e);
		}

	}

	private void disconnect() throws IOException{
		input.close();
		output.close();
		clientSocket.close();
	}

	private byte[] makeCookie() throws Exception{
		byte[] ip = this.clientSocket.getInetAddress().getAddress();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(ip);
		outputStream.write(this.cookieNonce);
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return md.digest(outputStream.toByteArray());
	}

	private boolean checkCookie(byte[] providedCookie) throws Exception{
		byte[] freshCookie = makeCookie();
		return (Arrays.equals(providedCookie, freshCookie));
	}


	//Returns the index of the clients login/session info if they are known. Returns -1 if they are unknown
	private int getClientIndex(String name){
		for(ClientEntry ce:clients){
			if(ce.name.equals(name)){
				return clients.indexOf(ce);
			}
		}
		return -1;
	}

	private boolean correctPassword(){
		return (Arrays.equals(pwHash, clients.get(clientIndex).pwHash));
	}

	private byte[] listClients() throws IOException{
		String listOfClients = "";
		for(ClientEntry ce:clients){
			if(!ce.name.equals(name) && ce.available){
				listOfClients += ("\n" + ce.name);
			}
		}	
		return listOfClients.getBytes();
	}
}













