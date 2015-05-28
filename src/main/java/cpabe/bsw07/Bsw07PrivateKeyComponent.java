package cpabe.bsw07;

import it.unisa.dia.gas.jpbc.Element;

public class Bsw07PrivateKeyComponent {
    /* these actually get serialized */
    /**
     * G2
     **/
    public Element hashedAttribute;
    /**
     * G2
     **/
    public Element d;
    /**
     * G2
     **/
    public Element dp;

    public Bsw07PrivateKeyComponent(Element hashedAttribute, Element d, Element dp) {
        this.hashedAttribute = hashedAttribute;
        this.d = d;
        this.dp = dp;
    }
}
