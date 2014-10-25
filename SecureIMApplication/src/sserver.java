import java.net.*;

public class sserver {

	public static void main(String[] args) {
		
		int serverPort = 7780;
		
		System.out.printf("Server Initialized on port %d \n", serverPort);
		final int MAX_UDP = 65507;
		
		try{
			// open a new UDP socket to listen to
			DatagramSocket serverSocket = new DatagramSocket(serverPort);
			
			while(true){
				
				DatagramPacket packetRcvd = new DatagramPacket(new byte[MAX_UDP], MAX_UDP);
				serverSocket.receive(packetRcvd);
				byte rcvdData[]= packetRcvd.getData();
				System.out.printf("Client %s sent %s \n", 
						packetRcvd.getSocketAddress().toString(),
						new String (rcvdData));
			
			}
		}
			catch(Exception e){
				e.printStackTrace();
			}
			}
}
