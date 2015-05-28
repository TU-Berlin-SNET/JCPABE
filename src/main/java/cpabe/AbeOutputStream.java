package cpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class AbeOutputStream extends DataOutputStream {

    private AbePublicKey pubKey;

    public AbeOutputStream(OutputStream out, AbePublicKey pubKey) {
        super(out);
        this.pubKey = pubKey;
    }

    // only used for the curve parameters and attributes, no need for fancy encodings
    public void writeString(String string) throws IOException {
        byte[] bytes = string.getBytes(AbeSettings.STRINGS_LOCALE);
        writeInt(bytes.length);
        write(bytes);
    }

    public void writeElement(Element elem) throws IOException {
        writeInt(pubKey.getPairing().getFieldIndex(elem.getField()));
        byte[] bytes = elem.toBytes();
        writeInt(bytes.length);
        write(bytes);
    }

}
