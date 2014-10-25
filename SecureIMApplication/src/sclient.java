import java.io.*;
import java.net.*;

public class sclient {

	static final int MAX_UDP = 65507;
	static DatagramSocket socket = null;
	
	public static void main(String[] args) throws InterruptedException, IOException {
		// public static something config = openf(*location*)
		// String srvIP = config[0]
		// int srvPort = config[1]
		// PublicKey srvPub = config[2]
		while(true) {
			Thread sndr = new Thread(new Sender());
			sndr.start();
			Thread.sleep(500);
		}
	}

	// Sending packets as a separate thread
	static class Sender implements Runnable{
		
		public void run() {
			
			BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
			String srvIP = "127.0.0.1"; // Read these from configuration file
			int srvPort = 7780;
			InetAddress srvAddr = null;
			
			// setup UDP socket
			try {
				socket = new DatagramSocket();
				srvAddr = InetAddress.getByName(srvIP);
			} catch (Exception e) {
					e.printStackTrace();
			}
			
			// sending packets
			try {
				byte[] data = new byte[MAX_UDP];
				data = stdin.readLine().getBytes();
				DatagramPacket sndPacket = new DatagramPacket(data, data.length, 
																srvAddr, srvPort);
				socket.send(sndPacket);
			} catch (IOException e) {
					e.printStackTrace();
			}
		}
	}
}
	
