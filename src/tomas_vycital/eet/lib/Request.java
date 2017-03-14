package tomas_vycital.eet.lib;

import tomas_vycital.eet.lib.exception.EETMissingValuesException;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.util.Formatter;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * Created by tom on 2017-02-28
 */
class Request {
    private final EETReceipt receipt;
    private String document;

    Request( EETReceipt receipt ) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, CertificateEncodingException, EETMissingValuesException {
        receipt.validate(); // Throws if the receipt_items is invalid

        this.receipt = receipt;
        this.document = ( new Scanner( Request.class.getResourceAsStream( "templates/request.xml" ) ) ).useDelimiter( "\\A" ).next();

        this.fillBody();
        this.generateCodes();
        this.addCertificate();
        this.sign();
    }

    private void replaceAttrPlaceholder( String placeholder, String value ) {
        this.document = this.document.replaceFirst( Pattern.quote( "\"→" + placeholder + "←\"" ), "\"" + value + "\"" );
    }

    private void replaceTagPlaceholder( String placeholder, String value ) {
        this.document = this.document.replaceFirst( Pattern.quote( "<!--" + placeholder + "-->" ), value );
    }

    private void fillBody() {
        for ( String attrName : EETReceipt.attrNames ) {
            String attrValue = this.receipt.get( attrName );
            if ( attrValue != null ) {
                this.replaceAttrPlaceholder( attrName, attrValue );
            }
        }
    }

    private void generateCodes() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, UnsupportedEncodingException {
        String plaintext = this.receipt.get( "dic_popl" )
                + "|" + this.receipt.get( "id_provoz" )
                + "|" + this.receipt.get( "id_pokl" )
                + "|" + this.receipt.get( "porad_cis" )
                + "|" + this.receipt.get( "dat_trzby" )
                + "|" + this.receipt.get( "celk_trzba" );

        Signature signature = Signature.getInstance( "SHA256withRSA" );
        signature.initSign( this.receipt.keyChain.getPrivateKey() );
        signature.update( plaintext.getBytes( "UTF-8" ) );

        byte[] rawPKP = signature.sign();
        String pkp = Base64.encode( rawPKP );

        MessageDigest crypt = MessageDigest.getInstance( "SHA-1" );
        crypt.reset();
        crypt.update( rawPKP );
        byte[] rawBKP = crypt.digest();

        Formatter formatter = new Formatter();
        for ( int i = 0; i < rawBKP.length; ++i ) {
            if ( i % 4 == 0 && i > 0 ) {
                formatter.format( "%s", "-" );
            }
            formatter.format( "%02x", rawBKP[i] );
        }
        String bkp = formatter.toString().toUpperCase();
        formatter.close();

        this.replaceTagPlaceholder( "pkp", pkp );
        this.replaceTagPlaceholder( "bkp", bkp );
        this.receipt.bkp = bkp;
        this.receipt.pkp = pkp;
    }

    private void addCertificate() throws CertificateEncodingException {
        this.replaceTagPlaceholder( "BinarySecurityToken", Base64.encode( this.receipt.keyChain.getCertificate().getEncoded() ) );
    }

    private void sign() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
        // Prepare body
        String body = this.document.replaceFirst( "[\\d\\D]*(<soap:Body[\\d\\D]*</soap:Body>)[\\d\\D]*", "$1" );
        body = this.uglifyXML( body );

        // Add digest
        MessageDigest md = MessageDigest.getInstance( "SHA-256" );
        md.update( body.getBytes( "UTF-8" ) );
        this.replaceTagPlaceholder( "DigestValue", Base64.encode( md.digest() ) );

        // Prepare signed info
        String signedInfo = this.document.replaceFirst( "[\\d\\D]*(<ds:SignedInfo[\\d\\D]*</ds:SignedInfo>)[\\d\\D]*", "$1" );
        signedInfo = this.uglifyXML( signedInfo );

        // Sign
        Signature signature = Signature.getInstance( "SHA256withRSA" );
        signature.initSign( this.receipt.keyChain.getPrivateKey() );
        signature.update( signedInfo.getBytes( "UTF-8" ) );

        this.replaceTagPlaceholder( "SignatureValue", Base64.encode( signature.sign() ) );
    }

    private String uglifyXML( String xml ) {
        return xml
                .replaceAll( "(<!--[^>]*-->|\\s+\\w+=\"→\\w+←\")", "" ) // Remove comments and placeholders
                .replaceAll( "(^|\n)\\s+", "$1" ) // Remove leading white spaces
                .replaceAll( "\\n<", "<" ) // Remove newlines in front of opening tags
                .replaceAll( ">\\n", ">" ) // Remove newlines after closing tags
                .replaceAll( "\\n", " " ) // Replace all remaining newlines by a space
                ;
    }

    String getString() {
        return this.uglifyXML( this.document.replaceAll( ">\\s*</(Hlavicka|Data)>", "/>" ) );
    }
}
