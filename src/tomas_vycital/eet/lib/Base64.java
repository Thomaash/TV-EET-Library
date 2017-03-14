package tomas_vycital.eet.lib;

/**
 * Created by tom on 2.3.17.
 * <p>
 * Just to make Android and desktop versions development easier.
 */

class Base64 {
    static String encode( byte[] data ) {
        // return android.util.Base64.encodeToString(data, android.util.Base64.DEFAULT);
        return java.util.Base64.getEncoder().encodeToString( data );
    }
}
