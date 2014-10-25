import java.security.*;

import javax.crypto.spec.DHParameterSpec;


public class DHGen {

	
	public static void main(String[] args){
		try {
	        // Create the parameter generator for a 1024-bit DH key pair
	        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
	        paramGen.init(1024);

	        // Generate the parameters
	        AlgorithmParameters params = paramGen.generateParameters();
	        DHParameterSpec dhSpec
	            = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

	        System.out.println(dhSpec.getP());
	        System.out.println(dhSpec.getG());
	        System.out.println(dhSpec.getL());
	        
	    } catch (Exception e) {
	    }
	}
}
