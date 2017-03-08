package tomas_vycital.eet.lib.exception;

/**
 * Created by tom on 3.3.17.
 */

public class EETMissingValuesException extends EETException {
    public EETMissingValuesException(String value) {
        super("Missing value in the receipt_items: " + value);
    }
}
