package th.or.etda.mobile;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.OperatorHelper;// force pulish
import org.bouncycastle.util.encoders.Base64;


public class util {

	byte[] signature ;
	PrivateKey privateKey = null;
	PublicKey publicKey = null;
	X509Certificate cert = null;
	List<X509Certificate> certChain = null;
	
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private String signatureAlgorithm;
    private AlgorithmIdentifier sigAlgId;
	
	public PublicKey getPublicKey() {
		return publicKey;
	}
	public byte[] getSignature() {
		return signature;
	}

	public String GsoftSignedData(String inputStr ,byte[] inputByte,String filePath, String inputFileP12 , String password) throws Exception {		
		 
		 byte[] data = null;
		 if(inputStr != null)
		 { data = inputStr.getBytes(); } 
		 else
		 {data = inputByte; }
			 
		 KeyStore ks = KeyStore.getInstance("PKCS12");
		 ks.load(new FileInputStream(filePath + inputFileP12), password.toCharArray());
	     
		 // BEGIN_INCLUDE(sign_load_keystore)
	     //KeyStore ks = KeyStore.getInstance("AndroidKeyStore");

	     // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
	     // to call "load", or it'll crash.
	     //ks.load(null);

	     // Load the key pair from the Android Key Store
	     //KeyStore.Entry entry = ks.getEntry("TH", null);

		 
		 Enumeration<String> aliases = ks.aliases();
			while(aliases.hasMoreElements()) {
	            String alias = (String)aliases.nextElement();	            
	            Key key = ks.getKey(alias, password.toCharArray());	            
	            if(key instanceof PrivateKey) {
		            privateKey = (PrivateKey) key;	            
		            cert = (X509Certificate) ks.getCertificate(alias);
		            publicKey = cert.getPublicKey(); 
	            }
	        }
				        
	        Signature sig = Signature.getInstance("SHA256withRSA");
	        sig.initSign(privateKey);
	        
	        sig.update(data);
	        signature = sig.sign();
	        System.out.println("from mobile :"+new String(signature)); 
	        
	        String result = Base64.toBase64String(signature);
	        
	        return result;
		
	}
	
	public boolean verify(byte[] input,PublicKey pubKey,String validateString) throws UnsupportedEncodingException, SignatureException, NoSuchAlgorithmException {
		
		Signature signature = Signature.getInstance("SHA256WithRSA");
		
		byte[] data = validateString.getBytes("UTF-8");	
		
		try {
			signature = Signature.getInstance("SHA256WithRSA");
			signature.initVerify(pubKey);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		signature.update(data);		
		
		return signature.verify(input);
	
	}
	
	public Signature init() {
		
		String filePath = "resources/";
		String inputFileP12 ="certificate.p12";
		String password = "Bass1234";
		
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 try {
			ks.load(new FileInputStream(filePath + inputFileP12), password.toCharArray());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
		 Enumeration<String> aliases = null;
		try {
			aliases = ks.aliases();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			while(aliases.hasMoreElements()) {
	            String alias = (String)aliases.nextElement();	            
	            Key key = null;
				try {
					key = ks.getKey(alias, password.toCharArray());
				} catch (UnrecoverableKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
	            if(key instanceof PrivateKey) 
	            {
		            privateKey = (PrivateKey) key;	            
		            try {
						cert = (X509Certificate) ks.getCertificate(alias);
					} catch (KeyStoreException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
		            publicKey = cert.getPublicKey(); 
	            }
	        }
			
			Signature sig = null;
			
			try {
				
				sig = Signature.getInstance("SHA256withRSA");
				sig.initSign(privateKey);
				
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}			
		
		return sig;		
	}
	
	public String getHash(InputStream is) throws IOException, NoSuchAlgorithmException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		   int nRead;
		   byte[] data = new byte[16384];
		   while ((nRead = is.read(data, 0, data.length)) != -1)
		     buffer.write(data, 0, nRead);
		   buffer.flush();
		   byte[] content = buffer.toByteArray();
		   
		   // digest
		   java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
		      byte[] hash = md.digest(content);                     
		         String hashEncoded = new String(Base64.encode(hash));                     
		         System.out.println("hash: "+hashEncoded);
		return hashEncoded;
	}
	
	public InputStream getInputStream(String filepath) throws FileNotFoundException {		
		InputStream targetStream = new FileInputStream(filepath);
		return targetStream;
	}
	
	public InputStream getInputStream(File file) throws FileNotFoundException {		
		InputStream targetStream = new FileInputStream(file);
		return targetStream;
	}
}

