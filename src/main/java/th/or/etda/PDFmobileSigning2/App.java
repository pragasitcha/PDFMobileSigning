package th.or.etda.PDFmobileSigning2;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SignatureException;


/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws SignatureException, IOException, GeneralSecurityException
    {
		/**** Sample Input ****/
		String passwordP12 = "Bass1234";
		String inputFileP12 = "certificate.p12";
		String inputFileName = "pdf.pdf";
		String outputFile = "mobilesigned_fromMobile.pdf";
		String filePath = "resources/";
		String urlTsaClient = "";
		String userTsaClient = "";
		String passwordTsaClient = "";
		
		
		SignAndTimeStamp.signWithTSA(passwordP12, inputFileP12, inputFileName, outputFile, filePath, urlTsaClient, userTsaClient, passwordTsaClient);


		System.out.println("********Sign And TimeStamp Done**********");
    }
}
