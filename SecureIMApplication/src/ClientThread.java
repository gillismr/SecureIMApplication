import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/*

class ClientThread extends Thread {
			
	private DataInputStream input = null;
	private DataOutputStream output = null;
	private Socket clientSocket = null;
	private final List<ClientEntry> clients;

	public ClientThread(Socket clientSocket, List<ClientEntry> clients) {
		this.clientSocket = clientSocket;
		this.clients = clients;
	}

	public void run() {
	
		try {
			
			input = new DataInputStream(clientSocket.getInputStream());
			output = new DataOutputStream(clientSocket.getOutputStream());
			
				
			while (true) {
				String line = input.toString();
				if (line.startsWith("/quit")) {
					break;
				}
			}
							
			input.close();
			output.close();
			clientSocket.close();
		} 
		catch (IOException e) {
		}
	}
	
	private void cookieExchange(){
		
	}
	
}
*/