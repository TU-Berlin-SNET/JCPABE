package cpabe.bsw07.policy;

import cpabe.AbeOutputStream;
import cpabe.AbePrivateKey;
import cpabe.AbePublicKey;
import cpabe.bsw07.Bsw07PrivateKeyComponent;
import cpabe.bsw07.Bsw07Util;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;

public class Bsw07PolicyLeafNode extends Bsw07PolicyAbstractNode {
    private Bsw07PrivateKeyComponent satisfyingComponent = null;
    /**
     * G2
     **/
    private Element hashedAttribute;
    /**
     * G1
     **/
    private Element c;
    /**
     * G1
     **/
    private Element cp;

    private Boolean isSatisfied = null;

    protected Bsw07PolicyLeafNode(Element hashedAttribute, Element c, Element cp) {
        this(hashedAttribute);
        this.c = c;
        this.cp = cp;
    }

    public Bsw07PolicyLeafNode(String attribute, AbePublicKey publicKey) {
        this(Bsw07Util.elementG2FromString(attribute, publicKey));
    }

    private Bsw07PolicyLeafNode(Element hashedAttribute) {
        this.hashedAttribute = hashedAttribute;
    }

    public int getThreshold() {
        return 1;
    }

    public Element getHashedAttribute() {
        return hashedAttribute;
    }

    @Override
    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeInt(getThreshold());
        stream.writeInt(0);
        stream.writeElement(hashedAttribute);
        stream.writeElement(c);
        stream.writeElement(cp);
    }

    @Override
    public void fillPolicy(AbePublicKey pub, Element e) {
        c = pub.g.duplicate().powZn(e);
        cp = hashedAttribute.duplicate().powZn(e);
    }

    @Override
    public boolean isSatisfiable(AbePrivateKey prv) {
        if (isSatisfied == null) {
            satisfyingComponent = prv.getSatisfyingComponent(getHashedAttribute());
            isSatisfied = satisfyingComponent != null;
        }
        return isSatisfied;
    }

    @Override
    public void pickSatisfyMinLeaves(AbePrivateKey prv) {
        minLeaves = 1;
    }

    @Override
    protected void decFlattenSpecific(Element r, Element exp, AbePrivateKey prv) {
        Element t = prv.getPublicKey().getPairing().pairing(cp, satisfyingComponent.dp).invert(); /* num_pairings++; */
        Element s = prv.getPublicKey().getPairing().pairing(c, satisfyingComponent.d).mul(t).powZn(exp); 
        /* num_pairings++ num_muls++ num_exps++ */
        r.mul(s); /* num_muls++; */
    }
}
