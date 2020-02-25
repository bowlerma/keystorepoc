/**
 * (c) Midland Software Limited 2020
 * Name     : KeyStorePoc.java
 * Author   : bowlerm
 * Date     : 24 Feb 2020
 */
package com.bowlerma.keystorepoc;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

/**
 *
 */
public class KeyStorePoc {

    private static final String KEYSTORE_NAME = "pkcs12";
    private static final String KEYSTORE_PROVIDER = "SunJSSE";
    private static final String KEYSTORE_PASSWORD = "";
    private static final String COREA_KEYSTORE_LOCATION = "/Users/bowlerm/pf-java-container-wildfly/p12";
    private static final String COREA_KEYSTORE_NAME = "E78DF7AB081D15C6287F2E4C87D2FB1FC30B7BC1.p12";

    private static final String COREA_ALIAS = "{a5a27f46-b0f7-4017-948d-6de397dd0e28}";

    private static final String ENCRYPTED_STRING = "5405EB00B303BB02F5A7C8022B04D2BB1F1C5098455AD3C190D37A4AB9B1768E65BC066F275D8A9DD7D1BDC302D5EB486B781669A1A11078FDCD46850FF24AF4BB5704F19574E7B5F4935B5C50006EC0883495997D911F5E4DD71CD1470BCC5709BBA891B44F54F59D32642E6DC6F47A09B42BAF5510DDCA096FCD366DB21FBA05D1631D51193CB9851982D64D30FAEAB13053A425E3D580AA59721428DCA064205D1424E757DEEEB52AF33C3F7630FD781F0B94BD118F1DBB19C8189C750B91DBE963DCB7A2FD528ECF8652B6413E6D4DB1500C9EAE0CD95120723ED856695C4F2C9AE275D20904A60250BEF589AE05E307B776FA76D7EDDA60841E5DE0741A";


    public static void main(String[] args)
            throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, InvalidCipherTextException {

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_NAME, KEYSTORE_PROVIDER);

        FileInputStream keyStoreStream = new FileInputStream(new File(COREA_KEYSTORE_LOCATION, COREA_KEYSTORE_NAME));

        keyStore.load(keyStoreStream, KEYSTORE_PASSWORD.toCharArray());

        Enumeration<String> aliases = keyStore.aliases();

        Key key = keyStore.getKey(keyStore.aliases().nextElement(), KEYSTORE_PASSWORD.toCharArray());

        String decryptedValue = new String(decryptRSA(DatatypeConverter.parseHexBinary(ENCRYPTED_STRING), key), StandardCharsets.UTF_8);

        System.out.println(decryptedValue);

  }

    private static byte[] decryptRSA(final byte[] encryptedData, final Key privateKey) throws IOException, InvalidCipherTextException {
        AsymmetricBlockCipher rsaPKCS1 = new RSAEngine();
        AsymmetricKeyParameter rsaPrivateKeyParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
        rsaPKCS1 = new PKCS1Encoding(rsaPKCS1);
        rsaPKCS1.init(false, rsaPrivateKeyParam);

        byte[] decrypted = null;
        // Decrypt the encrypted data.
        try {
            decrypted = rsaPKCS1.processBlock(encryptedData, 0, encryptedData.length);
        } catch (InvalidCipherTextException e) {
            AsymmetricBlockCipher rsaOAEP = new RSAEngine();
            rsaOAEP = new OAEPEncoding(rsaOAEP);
            rsaOAEP.init(false, rsaPrivateKeyParam);
                return rsaOAEP.processBlock(encryptedData, 0, encryptedData.length);
        }
        return decrypted;
    }
}
