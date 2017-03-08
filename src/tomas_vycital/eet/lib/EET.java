package tomas_vycital.eet.lib;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;

import tomas_vycital.eet.lib.exception.EETException;

/**
 * @author tom
 */
public class EET {

    private static URL urlPlay;
    private static URL urlProd;

    static {
        try {
            EET.urlPlay = new URL("https://pg.eet.cz/eet/services/EETServiceSOAP/v3");
        } catch (MalformedURLException e) {
            EET.urlPlay = null;
        }
        try {
            EET.urlProd = new URL("https://prod.eet.cz/eet/services/EETServiceSOAP/v3");
        } catch (MalformedURLException e) {
            EET.urlPlay = null;
        }
    }

    private final URL url;

    public EET() {
        this(false);
    }

    public EET(boolean playground) {
        if (playground) {
            this.url = EET.urlPlay;
        } else {
            this.url = EET.urlProd;
        }
    }

    private static String send(EETReceipt receipt, URL url) throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, InvalidKeyException, IOException, EETException {
        Request request = new Request(receipt);

        receipt.request = request.getString();
        byte[] soapMessage = receipt.request.getBytes("UTF-8");

        // Prepare a connection
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setUseCaches(false);
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "text/xml");
        connection.setRequestProperty("charset", "UTF-8");
        connection.setRequestProperty("Content-Length", "" + soapMessage.length);

        // Write the message
        OutputStream os = connection.getOutputStream();
        os.write(soapMessage);
        os.flush();
        os.close();

        // Get the response
        Response response = new Response(connection.getInputStream());

        // Disconnect
        connection.disconnect();
        receipt.setPrvniZaslani(false);
        receipt.response = response.getString();
        receipt.fik = response.getFIK();

        return response.getFIK() != null ? response.getFIK() : receipt.pkp;
    }

    public static String sendPlay(EETReceipt receipt) throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, InvalidKeyException, IOException, EETException {
        return EET.send(receipt, EET.urlPlay);
    }

    public static String sendProd(EETReceipt receipt) throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, InvalidKeyException, IOException, EETException {
        return EET.send(receipt, EET.urlProd);
    }

    public String send(EETReceipt receipt) throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, InvalidKeyException, IOException, EETException {
        return EET.send(receipt, this.url);
    }

}
