package tomas_vycital.eet.lib.exception;

/**
 * Created by tom on 3.3.17.
 */

public class EETServerException extends EETException {
    private final Integer code;

    public EETServerException() {
        super("Something went wrong.");
        this.code = null;
    }

    public EETServerException(int code, String text) {
        super(text);
        this.code = code;
    }

    public Integer getCode() {
        return this.code;
    }
}
