package cpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.io.*;

public class AbePublicKey {
    /**
     * G_1
     **/
    public Element g;
    /**
     * G_1
     **/
    public Element h;
    /**
     * G_1
     **/
    public Element f;
    /**
     * G_T
     **/
    public Element e_g_g_hat_alpha;
    /*
     * A public key
     */
    private String pairingDesc;
    private transient Pairing p;

    /**
     * Creates a new AbePublicKey. This key should only be used after the elements have been set (setElements).
     *
     * @param pairingDescription
     */
    public AbePublicKey(String pairingDescription) {
        this.pairingDesc = pairingDescription;
    }

    public static AbePublicKey readFromFile(File file) throws IOException {
        try (AbeInputStream stream = new AbeInputStream(new FileInputStream(file))) {
            return readFromStream(stream);
        }
    }

    public static AbePublicKey readFromStream(AbeInputStream stream) throws IOException {
        String pairingDescription = stream.readString();
        AbePublicKey publicKey = new AbePublicKey(pairingDescription);
        stream.setPublicKey(publicKey);
        publicKey.g = stream.readElement();
        publicKey.h = stream.readElement();
        publicKey.f = stream.readElement();
        publicKey.e_g_g_hat_alpha = stream.readElement();
        return publicKey;
    }

    public String getPairingDescription() {
        return pairingDesc;
    }

    public Pairing getPairing() {
        if (p == null) {
            PairingParameters params = new PropertiesParameters().load(new ByteArrayInputStream(pairingDesc.getBytes()));
            p = PairingFactory.getPairing(params);
        }
        return p;
    }

    public void setElements(Element g, Element h, Element f, Element e_g_g_hat_alpha) {
        this.g = g;
        this.h = h;
        this.f = f;
        this.e_g_g_hat_alpha = e_g_g_hat_alpha;
    }

    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeString(pairingDesc);
        stream.writeElement(g);
        stream.writeElement(h);
        stream.writeElement(f);
        stream.writeElement(e_g_g_hat_alpha);
    }

    public void writeToFile(File file) throws IOException {
        try (AbeOutputStream fos = new AbeOutputStream(new FileOutputStream(file), this)) {
            writeToStream(fos);
        }
    }
}
