package cpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class AbeInputStream extends DataInputStream {
    private final String PUB_MISSING_ERROR = "Can't read Elements without the public master key.";

    private AbePublicKey publicKey;

    public AbeInputStream(InputStream in, AbePublicKey publicKey) {
        super(in);
        this.publicKey = publicKey;
    }

    /**
     * If you use this constructor you need to manually set the public key before reading any elements.
     *
     * @param in
     */
    public AbeInputStream(InputStream in) {
        this(in, null);
    }

    public void setPublicKey(AbePublicKey pubKey) {
        this.publicKey = pubKey;
    }

    // only used for the curve parameters and attributes, no need for fancy encodings
    // since internal attribute representation only uses [a-zA-Z0-9:_]
    public String readString() throws IOException {
        int length = readInt();
        byte[] bytes = new byte[length];
        readFully(bytes);
        return new String(bytes, AbeSettings.STRINGS_LOCALE);
    }

    public Element readElement() throws IOException {
        if (publicKey == null) throw new IOException(PUB_MISSING_ERROR);
        int fieldIndex = readInt();
        int length = readInt();
        byte[] bytes = new byte[length];
        readFully(bytes);
        return publicKey.getPairing().getFieldAt(fieldIndex).newElementFromBytes(bytes);
    }
}
