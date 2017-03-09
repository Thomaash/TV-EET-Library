package tomas_vycital.eet.lib;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Formatter;
import java.util.regex.Pattern;

import tomas_vycital.eet.lib.exception.EETMissingValuesException;

/**
 * Created by tom on 2017-02-28
 */
class Request {
    private static String template = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
            "    <soap:Header>\n" +
            "        <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"\n" +
            "                       xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"\n" +
            "                       soap:mustUnderstand=\"1\">\n" +
            "            <wsse:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\"\n" +
            "                                      ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"\n" +
            "                                      wsu:Id=\"X509-AB79979F3364F5119A14761286403811\">\n" +
            "                <!--BinarySecurityToken-->\n" +
            "            </wsse:BinarySecurityToken>\n" +
            "            <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n" +
            "                          Id=\"SIG-AB79979F3364F5119A14761286404065\">\n" +
            "                <ds:SignedInfo\n" +
            "                        xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n" +
            "                        xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
            "                    <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">\n" +
            "                        <ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\"\n" +
            "                                                PrefixList=\"soap\">\n" +
            "                        </ec:InclusiveNamespaces>\n" +
            "                    </ds:CanonicalizationMethod>\n" +
            "                    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\">\n" +
            "                    </ds:SignatureMethod>\n" +
            "                    <ds:Reference URI=\"#id-AB79979F3364F5119A14761286403964\">\n" +
            "                        <ds:Transforms>\n" +
            "                            <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">\n" +
            "                                <ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\"\n" +
            "                                                        PrefixList=\"\">\n" +
            "                                </ec:InclusiveNamespaces>\n" +
            "                            </ds:Transform>\n" +
            "                        </ds:Transforms>\n" +
            "                        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\">\n" +
            "                        </ds:DigestMethod>\n" +
            "                        <ds:DigestValue>\n" +
            "                            <!--DigestValue-->\n" +
            "                        </ds:DigestValue>\n" +
            "                    </ds:Reference>\n" +
            "                </ds:SignedInfo>\n" +
            "                <ds:SignatureValue>\n" +
            "                    <!--SignatureValue-->\n" +
            "                </ds:SignatureValue>\n" +
            "                <ds:KeyInfo Id=\"KI-AB79979F3364F5119A14761286403862\">\n" +
            "                    <wsse:SecurityTokenReference wsu:Id=\"STR-AB79979F3364F5119A14761286403893\">\n" +
            "                        <wsse:Reference URI=\"#X509-AB79979F3364F5119A14761286403811\"\n" +
            "                                        ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\">\n" +
            "                        </wsse:Reference>\n" +
            "                    </wsse:SecurityTokenReference>\n" +
            "                </ds:KeyInfo>\n" +
            "            </ds:Signature>\n" +
            "        </wsse:Security>\n" +
            "    </soap:Header>\n" +
            "    <soap:Body xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"\n" +
            "               xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"\n" +
            "               wsu:Id=\"id-AB79979F3364F5119A14761286403964\">\n" +
            "        <Trzba xmlns=\"http://fs.mfcr.cz/eet/schema/v3\">\n" +
            "            <Hlavicka dat_odesl=\"→dat_odesl←\"\n" +
            "                      overeni=\"→overeni←\"\n" +
            "                      prvni_zaslani=\"→prvni_zaslani←\"\n" +
            "                      uuid_zpravy=\"→uuid_zpravy←\">\n" +
            "            </Hlavicka>\n" +
            "            <Data celk_trzba=\"→celk_trzba←\"\n" +
            "                  cerp_zuct=\"→cerp_zuct←\"\n" +
            "                  cest_sluz=\"→cest_sluz←\"\n" +
            "                  dan1=\"→dan1←\"\n" +
            "                  dan2=\"→dan2←\"\n" +
            "                  dan3=\"→dan3←\"\n" +
            "                  dat_trzby=\"→dat_trzby←\"\n" +
            "                  dic_popl=\"→dic_popl←\"\n" +
            "                  id_pokl=\"→id_pokl←\"\n" +
            "                  id_provoz=\"→id_provoz←\"\n" +
            "                  porad_cis=\"→porad_cis←\"\n" +
            "                  pouzit_zboz1=\"→pouzit_zboz1←\"\n" +
            "                  pouzit_zboz2=\"→pouzit_zboz2←\"\n" +
            "                  pouzit_zboz3=\"→pouzit_zboz3←\"\n" +
            "                  rezim=\"→rezim←\"\n" +
            "                  urceno_cerp_zuct=\"→urceno_cerp_zuct←\"\n" +
            "                  zakl_dan1=\"→zakl_dan1←\"\n" +
            "                  zakl_dan2=\"→zakl_dan2←\"\n" +
            "                  zakl_dan3=\"→zakl_dan3←\"\n" +
            "                  zakl_nepodl_dph=\"→zakl_nepodl_dph←\">\n" +
            "            </Data>\n" +
            "            <KontrolniKody>\n" +
            "                <pkp cipher=\"RSA2048\"\n" +
            "                     digest=\"SHA256\"\n" +
            "                     encoding=\"base64\">\n" +
            "                    <!--pkp-->\n" +
            "                </pkp>\n" +
            "                <bkp digest=\"SHA1\"\n" +
            "                     encoding=\"base16\">\n" +
            "                    <!--bkp-->\n" +
            "                </bkp>\n" +
            "            </KontrolniKody>\n" +
            "        </Trzba>\n" +
            "    </soap:Body>\n" +
            "</soap:Envelope>";

    private final EETReceipt receipt;
    private String document;

    Request(EETReceipt receipt) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, CertificateEncodingException, EETMissingValuesException {
        receipt.validate(); // Throws if the receipt_items is invalid

        this.receipt = receipt;
        //this.document = new Scanner( EET.class.getResourceAsStream( "templates/request.xml" ), "UTF-8" ).useDelimiter( "\\A" ).next();
        this.document = Request.template;

        this.fillBody();
        this.generateCodes();
        this.addCertificate();
        this.sign();
    }

    private void replaceAttrPlaceholder(String placeholder, String value) {
        this.document = this.document.replaceFirst(Pattern.quote("\"→" + placeholder + "←\""), "\"" + value + "\"");
    }

    private void replaceTagPlaceholder(String placeholder, String value) {
        this.document = this.document.replaceFirst(Pattern.quote("<!--" + placeholder + "-->"), value);
    }

    private void fillBody() {
        for (String attrName : EETReceipt.attrNames) {
            String attrValue = this.receipt.get(attrName);
            if (attrValue != null) {
                this.replaceAttrPlaceholder(attrName, attrValue);
            }
        }
    }

    private void generateCodes() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, UnsupportedEncodingException {
        String plaintext = this.receipt.get("dic_popl")
                + "|" + this.receipt.get("id_provoz")
                + "|" + this.receipt.get("id_pokl")
                + "|" + this.receipt.get("porad_cis")
                + "|" + this.receipt.get("dat_trzby")
                + "|" + this.receipt.get("celk_trzba");

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.receipt.keyChain.getPrivateKey());
        signature.update(plaintext.getBytes("UTF-8"));

        byte[] rawPKP = signature.sign();
        String pkp = Base64.encode(rawPKP);

        MessageDigest crypt = MessageDigest.getInstance("SHA-1");
        crypt.reset();
        crypt.update(rawPKP);
        byte[] rawBKP = crypt.digest();

        Formatter formatter = new Formatter();
        for (int i = 0; i < rawBKP.length; ++i) {
            if (i % 4 == 0 && i > 0) {
                formatter.format("%s", "-");
            }
            formatter.format("%02x", rawBKP[i]);
        }
        String bkp = formatter.toString().toUpperCase();
        formatter.close();

        this.replaceTagPlaceholder("pkp", pkp);
        this.replaceTagPlaceholder("bkp", bkp);
        this.receipt.bkp = bkp;
        this.receipt.pkp = pkp;
    }

    private void addCertificate() throws CertificateEncodingException {
        this.replaceTagPlaceholder("BinarySecurityToken", Base64.encode(this.receipt.keyChain.getCertificate().getEncoded()));
    }

    private void sign() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
        // Prepare body
        String body = this.document.replaceFirst("[\\d\\D]*(<soap:Body[\\d\\D]*</soap:Body>)[\\d\\D]*", "$1");
        body = this.uglifyXML(body);

        // Add digest
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(body.getBytes("UTF-8"));
        this.replaceTagPlaceholder("DigestValue", Base64.encode(md.digest()));

        // Prepare signed info
        String signedInfo = this.document.replaceFirst("[\\d\\D]*(<ds:SignedInfo[\\d\\D]*</ds:SignedInfo>)[\\d\\D]*", "$1");
        signedInfo = this.uglifyXML(signedInfo);

        // Sign
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.receipt.keyChain.getPrivateKey());
        signature.update(signedInfo.getBytes("UTF-8"));

        this.replaceTagPlaceholder("SignatureValue", Base64.encode(signature.sign()));
    }

    private String uglifyXML(String xml) {
        return xml
                .replaceAll("(<!--[^>]*-->|\\s+\\w+=\"→\\w+←\")", "") // Remove comments and placeholders
                .replaceAll("(^|\n)\\s+", "$1") // Remove leading white spaces
                .replaceAll("\\n<", "<") // Remove newlines in front of opening tags
                .replaceAll(">\\n", ">") // Remove newlines after closing tags
                .replaceAll("\\n", " ") // Replace all remaining newlines by a space
                ;
    }

    String getString() {
        return this.uglifyXML(this.document.replaceAll(">\\s*</(Hlavicka|Data)>", "/>"));
    }
}
