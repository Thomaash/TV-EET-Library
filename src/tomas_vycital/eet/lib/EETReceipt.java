package tomas_vycital.eet.lib;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.UUID;

import tomas_vycital.eet.lib.exception.EETMissingValuesException;

/**
 * @author tom
 */
@SuppressWarnings({"WeakerAccess", "SameParameterValue"})
public class EETReceipt {
    final static String[] attrNames = new String[]{"dic_popl", "id_provoz", "id_pokl", "porad_cis", "dat_trzby", "celk_trzba", "dat_odesl", "uuid_zpravy", "prvni_zaslani", "dic_poverujiciho", "overeni", "zakl_nepodl_dph", "zakl_dan1", "dan1", "zakl_dan2", "dan2", "zakl_dan3", "dan3", "cest_sluz", "pouzit_zboz1", "pouzit_zboz2", "pouzit_zboz3", "urceno_cerp_zuct", "cerp_zuct", "rezim"};
    private final static String[] mandatoryAttrNames = new String[]{"dic_popl", "id_provoz", "id_pokl", "porad_cis", "dat_trzby", "celk_trzba", "dat_odesl", "uuid_zpravy", "prvni_zaslani", "rezim"};
    private final HashMap<String, String> attrValues;
    Keychain keyChain;
    String bkp;
    String pkp;
    String fik;

    String request;
    String response;

    public EETReceipt() {
        this.attrValues = new HashMap<>();

        this.setDatOdesl(this.getCurrentTime());
        this.setUuidZpravy(UUID.randomUUID().toString());
        this.setPrvniZaslani(true);

        this.bkp = null;
        this.pkp = null;
        this.fik = null;

        this.request = null;
        this.response = null;
    }

    String get(String attr) {
        return this.attrValues.get(attr);
    }

    String set(String attr, String value) {
        return this.attrValues.put(attr, value);
    }

    public String getMissingValue() {
        for (String key : EETReceipt.mandatoryAttrNames) {
            if (this.attrValues.get(key) == null) {
                return key;
            }
        }
        return null;
    }

    public boolean isValid() {
        return this.getMissingValue() == null;
    }

    public void validate() throws EETMissingValuesException {
        String missing = this.getMissingValue();
        if (missing != null) {
            throw new EETMissingValuesException(missing);
        }
    }

    private String getCurrentTime() {
        return this.formatDate(new Date());
    }

    private String formatDate(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(date);
    }

    private String halersToString(int halers) {
        return String.format(halers < 0 ? "%04d" : "%03d", halers).replaceFirst("^(.*)(.{2})$", "$1.$2");
    }

    public EETReceipt setP12(InputStream file, char[] password) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.keyChain = new Keychain(file, password);
        return this;
    }

    public EETReceipt setDicPopl(String value) {
        this.attrValues.put("dic_popl", value);
        return this;
    }

    public EETReceipt setIdProvoz(String value) {
        this.attrValues.put("id_provoz", value);
        return this;
    }

    public EETReceipt setIdPokl(String value) {
        this.attrValues.put("id_pokl", value);
        return this;
    }

    public EETReceipt setPoradCis(String value) {
        this.attrValues.put("porad_cis", value);
        return this;
    }

    public EETReceipt setDatTrzby(Date value) {
        this.attrValues.put("dat_trzby", this.formatDate(value));
        return this;
    }

    public EETReceipt setCelkTrzba(int value) {
        this.attrValues.put("celk_trzba", this.halersToString(value));
        return this;
    }

    public EETReceipt setDatOdesl(String value) {
        this.attrValues.put("dat_odesl", value);
        return this;
    }

    public EETReceipt setUuidZpravy(String value) {
        this.attrValues.put("uuid_zpravy", value);
        return this;
    }

    public EETReceipt setPrvniZaslani(boolean value) {
        this.attrValues.put("prvni_zaslani", value ? "true" : "false");
        return this;
    }

    public EETReceipt setDicPoverujiciho(String value) {
        this.attrValues.put("dic_poverujiciho", value);
        return this;
    }

    public EETReceipt setOvereni(boolean value) {
        this.attrValues.put("overeni", value ? "true" : "false");
        return this;
    }

    public EETReceipt setZaklNepodlDph(int value) {
        this.attrValues.put("zakl_nepodl_dph", this.halersToString(value));
        return this;
    }

    public EETReceipt setZaklDan1(int value) {
        this.attrValues.put("zakl_dan1", this.halersToString(value));
        return this;
    }

    public EETReceipt setDan1(int value) {
        this.attrValues.put("dan1", this.halersToString(value));
        return this;
    }

    public EETReceipt setZaklDan2(int value) {
        this.attrValues.put("zakl_dan2", this.halersToString(value));
        return this;
    }

    public EETReceipt setDan2(int value) {
        this.attrValues.put("dan2", this.halersToString(value));
        return this;
    }

    public EETReceipt setZaklDan3(int value) {
        this.attrValues.put("zakl_dan3", this.halersToString(value));
        return this;
    }

    public EETReceipt setDan3(int value) {
        this.attrValues.put("dan3", this.halersToString(value));
        return this;
    }

    public EETReceipt setCestSluz(int value) {
        this.attrValues.put("cest_sluz", this.halersToString(value));
        return this;
    }

    public EETReceipt setPouzitZboz1(int value) {
        this.attrValues.put("pouzit_zboz1", this.halersToString(value));
        return this;
    }

    public EETReceipt setPouzitZboz2(int value) {
        this.attrValues.put("pouzit_zboz2", this.halersToString(value));
        return this;
    }

    public EETReceipt setPouzitZboz3(int value) {
        this.attrValues.put("pouzit_zboz3", this.halersToString(value));
        return this;
    }

    public EETReceipt setUrcenoCerpZuct(int value) {
        this.attrValues.put("urceno_cerp_zuct", this.halersToString(value));
        return this;
    }

    public EETReceipt setCerpZuct(int value) {
        this.attrValues.put("cerp_zuct", this.halersToString(value));
        return this;
    }

    public EETReceipt setRezim(int value) {
        this.attrValues.put("rezim", Integer.toString(value));
        return this;
    }

    public String getBKP() {
        return this.bkp;
    }

    public String getPKP() {
        return this.pkp;
    }

    public String getFIK() {
        return this.fik;
    }

    public String getRequest() {
        return this.request;
    }

    public String getResponse() {
        return this.response;
    }
}
