package cpabe.bsw07;

import it.unisa.dia.gas.jpbc.Element;

public class Bsw07CipherAndKey {
    private Bsw07Cipher cipher;
    private Element key;

    public Bsw07CipherAndKey(Bsw07Cipher cipher, Element key) {
        this.cipher = cipher;
        this.key = key;
    }

    public Bsw07Cipher getCipher() {
        return cipher;
    }

    public Element getKey() {
        return key;
    }
}
