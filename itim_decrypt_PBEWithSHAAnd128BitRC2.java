// PBE/SHA1/RC2/CBC/PKCS12PBE-5-128 decryptor
// Compile with
// 		javac -XDignore.symbol.file -cp jsafe.jar itim_decrypt_PBEWithSHAAnd128BitRC2.java
// Run as the following on Linux
//		java -cp .:jsafe.jar itim_decrypt_PBEWithSHAAnd128BitRC2 [base64 encoded text] [encryption password]
//   or on Windows
//		java -cp .;jsafe.jar itim_decrypt_PBEWithSHAAnd128BitRC2 [base64 encoded text] [encryption password]
// Notice -cp (classpath) adds the current folder which is dot colon on Linux or dot semicolon on Windows

import com.rsa.jsafe.JSAFE_Exception;
import com.rsa.jsafe.JSAFE_SecretKey;
import com.rsa.jsafe.JSAFE_SymmetricCipher;

import java.util.Arrays;
import sun.misc.BASE64Decoder;

public class itim_decrypt_PBEWithSHAAnd128BitRC2 {
	static String algorithmType="PBE/SHA1/RC2/CBC/PKCS12PBE-5-128";
    final protected static char[] hexArray = "0123456789abcdef".toCharArray();

	public static void main(String[] args){
		if (args.length < 2){
			System.out.println("Need two args, data, pass");
			System.exit(1);
		}
		char[] cipherPassword=args[1].toCharArray();
		try{
			JSAFE_SymmetricCipher decryptor = JSAFE_SymmetricCipher.getInstance(algorithmType, "Java");
	    	JSAFE_SecretKey decryptSecretKey = decryptor.getBlankKey();
	    	decryptSecretKey.setPassword(cipherPassword, 0, cipherPassword.length);
	    	decryptor.decryptInit(decryptSecretKey);

            byte[] cipherText = new BASE64Decoder().decodeBuffer(args[0]);
            byte[] clearText = new byte[cipherText.length];

            int p = decryptor.decryptUpdate(cipherText, 0, cipherText.length, clearText, 0);
            int c = decryptor.decryptFinal(clearText, p)+p;
            if (clearText.length > c) {
              byte[] out = new byte[c];
              System.arraycopy(clearText, 0, out, 0, c);
              Arrays.fill(clearText, (byte)0);
              clearText = out;
            }
			//System.out.println("\nkey="+hexlify(decryptSecretKey.getSecretKeyData())+" iv="+hexlify(decryptor.getIV()));
			System.out.println(new String(clearText));
	    } catch (Exception e)  {
    	    System.out.println("Exception during decryption");
      		System.out.println(e.getMessage());
      		System.exit(1);
    	}

	}

    public static String hexlify(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        String ret = new String(hexChars);
        return ret;
    }

}
