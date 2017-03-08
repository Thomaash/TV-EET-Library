package tomas_vycital.eet.lib;

import java.io.InputStream;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import tomas_vycital.eet.lib.exception.EETServerException;

/**
 * Created by tom on 2017-03-01
 */
class Response {
    private static final Pattern regexFIK = Pattern.compile("[\\d\\D]*fik=\"([^\"]+)\"[\\d\\D]*");
    private static final Pattern regexErrorText = Pattern.compile("[\\d\\D]*<eet:Chyba[\\d\\D]*kod=\"(-?\\d+)\"[\\d\\D]*>([^\\n<>]+)</eet:Chyba>[\\d\\D]*");
    private final String document;

    Response(InputStream inputStream) {
        this.document = new Scanner(inputStream, "UTF-8").useDelimiter("\\A").next();
    }

    private EETServerException getException() {
        Matcher matcher = Response.regexErrorText.matcher(this.document);
        if (matcher.find()) {
            return new EETServerException(Integer.valueOf(matcher.group(1)), matcher.group(2));
        } else {
            return new EETServerException();
        }
    }

    String getFIK() throws EETServerException {
        Matcher matcher = Response.regexFIK.matcher(this.document);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            throw this.getException();
        }
    }

    String getString() {
        return this.document;
    }
}
