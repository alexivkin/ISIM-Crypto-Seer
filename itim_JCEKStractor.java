/*
 Extracts itim cipher key from /opt/IBM/isim/data/keystore/itimKeystore.jceks

 Compiling:
 /opt/IBM/WebSphere/AppServer/java/bin/javac itim_JCEKStractor.java

 Running:
 /opt/IBM/WebSphere/AppServer/java/bin/java itim_JCEKStractor /opt/IBM/isim/data/keystore/itimKeystore.jceks jceks-access-password

 jceks-access-password is the ISIM master key

If you see "com.ibm.crypto.provider.AESSecretKey" as the result, install ibmjceprovider.jar or run it on a JVM with the IBM Crypto provider installed (e.g WAS JVM)
add security provider to your java.security
echo "security.provider.10=com.ibm.crypto.provider.IBMJCE" | sudo tee -a $(dirname "$(readlink -f $(which java))")/../lib/security/java.security
and copy ibmjceprovider.jar to your classpath
sudo cp ibmjceprovider.jar $(dirname "$(readlink -f $(which java))")/../lib/ext/

More info on [Installing Providers for JCE](https://www.ibm.com/support/knowledgecenter/en/SSYKE2_7.0.0/com.ibm.java.security.component.70.doc/security-component/JceDocs/installingproviders.html)
the actual lib is distributed with the [IBM JDK](https://www.ibm.com/developerworks/java/jdk/java8/) inside lib/ext/

*/

import java.io.File;
import sun.misc.BASE64Encoder;
import java.io.FileInputStream;
import java.security.KeyStore;
import javax.crypto.SecretKey;

public class itim_JCEKStractor {
	public static void main(String[] args){
		if (args.length < 2){
			System.out.println("Need two args - location of jceks and a password");
			System.exit(1);
		}
		BASE64Encoder base64 = new BASE64Encoder();
		try {
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(new File(args[0])), args[1].toCharArray());
			SecretKey key = (SecretKey)ks.getKey("itimcipherkey", args[1].toCharArray());
			System.out.println(new String(base64.encode(key.getEncoded())));
			//System.out.println(new String(key.getAlgorithm()));
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}
	}
}
