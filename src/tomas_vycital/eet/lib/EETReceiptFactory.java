package tomas_vycital.eet.lib;

/**
 * Creates new receipts based on the template receipt_items submitted in the constructor.
 */

public class EETReceiptFactory {

    private final EETReceipt receipt;

    public EETReceiptFactory( EETReceipt receipt ) {
        this.receipt = receipt;
    }

    public EETReceipt generate() {
        EETReceipt receipt = new EETReceipt();

        for ( String attr : EETReceipt.attrNames ) {
            String value = this.receipt.get( attr );
            if ( value != null ) {
                receipt.set( attr, value );
            }
        }

        return receipt;
    }

}
