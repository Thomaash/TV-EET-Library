package tomas_vycital.eet.lib;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;

/**
 * @author tom
 */
class Keychain {

    private PrivateKey key;
    private X509Certificate certificate;

    Keychain( InputStream file, char[] password ) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance( "PKCS12" );
        keyStore.load( file, password );

        Enumeration<String> aliases = keyStore.aliases();
        while ( aliases.hasMoreElements() ) {
            String alias = aliases.nextElement();

            Key key = keyStore.getKey( alias, password );
            Certificate certificate = keyStore.getCertificate( alias );
            if ( key != null && certificate != null && key instanceof RSAPrivateKey && certificate instanceof X509Certificate ) {
                this.key = (PrivateKey) key;
                this.certificate = (X509Certificate) certificate;
                break;
            }
        }
    }

    PrivateKey getPrivateKey() {
        return this.key;
    }

    X509Certificate getCertificate() {
        return this.certificate;
    }
}
