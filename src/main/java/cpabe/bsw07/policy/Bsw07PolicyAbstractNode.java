package cpabe.bsw07.policy;

import cpabe.*;
import it.unisa.dia.gas.jpbc.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class Bsw07PolicyAbstractNode {
    protected int minLeaves;

    public static Bsw07PolicyAbstractNode readFromStream(AbeInputStream stream) throws IOException {
        int threshold = stream.readInt();
        int numberOfChildren = stream.readInt();
        if (numberOfChildren == 0) { // is leaf
            Element hashedAttribute = stream.readElement();
            Element c = stream.readElement();
            Element cp = stream.readElement();
            return new Bsw07PolicyLeafNode(hashedAttribute, c, cp);
        } else {
            Bsw07PolicyParentNode tmp = new Bsw07PolicyParentNode(threshold, numberOfChildren);
            for (int i = 0; i < numberOfChildren; i++) {
                Bsw07PolicyAbstractNode readPolicy = Bsw07PolicyAbstractNode.readFromStream(stream);
                tmp.addChild(readPolicy);
            }
            return tmp;
        }
    }

    private static final String of = "([0-9]+)of([0-9]+)";
    private static final Pattern ofPattern = Pattern.compile(of);

    public static Bsw07PolicyAbstractNode parsePolicy(String s, AbePublicKey publicKey) throws AbeEncryptionException {
        ArrayList<Bsw07PolicyAbstractNode> stack = new ArrayList<Bsw07PolicyAbstractNode>();
        String[] toks = s.split("\\s+");
        for (int index = 0; index < toks.length; index++) {
            String curToken = toks[index];
            Matcher matcher = ofPattern.matcher(curToken);
            if (!matcher.matches()) {
                stack.add(new Bsw07PolicyLeafNode(curToken, publicKey));
            } else {
                int threshold = Integer.parseInt(matcher.group(1));
                int numChildren = Integer.parseInt(matcher.group(2));

                if (threshold < 1) {
                    throw new AbeEncryptionException("error parsing " + s + ": trivially satisfied operator " + curToken);
                } else if (threshold > numChildren) {
                    throw new AbeEncryptionException("error parsing " + s + ": unsatisfiable operator " + curToken);
                } else if (numChildren == 1) {
                    System.err.println("error parsing " + s + ": redundant operator " + curToken);
                } else if (numChildren > stack.size()) {
                    throw new AbeEncryptionException("error parsing " + s + ": stack underflow at " + curToken);
                }

                /* pop n things and fill in children */
                Bsw07PolicyParentNode node = new Bsw07PolicyParentNode(threshold, numChildren);
                Bsw07PolicyAbstractNode[] tmp = new Bsw07PolicyAbstractNode[numChildren];

                for (int i = numChildren - 1; i >= 0; i--)
                    tmp[i] = stack.remove(stack.size() - 1);

                node.addAllChildren(Arrays.asList(tmp));
                /* push result */
                stack.add(node);
            }
        }

        if (stack.size() > 1) {
            throw new AbeEncryptionException("error parsing " + s + ": extra node left on the stack");
        } else if (stack.size() < 1) {
            throw new AbeEncryptionException("error parsing " + s + ": empty policy");
        }
        return stack.get(0); // the root of the tree
    }

    public abstract void fillPolicy(AbePublicKey pub, Element e);

    public abstract boolean isSatisfiable(AbePrivateKey prv);

    public abstract void pickSatisfyMinLeaves(AbePrivateKey prv) throws AbeDecryptionException;

    protected abstract void decFlattenSpecific(Element r, Element one, AbePrivateKey prv);

    public void decFlatten(Element r, AbePrivateKey prv) {
        Element one = prv.getPublicKey().getPairing().getZr().newOneElement();
        r.setToOne();
        decFlattenSpecific(r, one, prv);
    }

    public abstract int getThreshold();

    public abstract void writeToStream(AbeOutputStream stream) throws IOException;

    public Bsw07PolicyAbstractNode getCopy(AbePublicKey publicKey) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             AbeOutputStream abeOutputStream = new AbeOutputStream(baos, publicKey)) {
            writeToStream(abeOutputStream);
            abeOutputStream.flush();
            byte[] serializedPolicyTree = baos.toByteArray();
            try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedPolicyTree);
                 AbeInputStream abeIs = new AbeInputStream(bais, publicKey)) {
                return Bsw07PolicyAbstractNode.readFromStream(abeIs);
            }
        }

    }
}
