package cpabe.bsw07.policy;

import cpabe.AbeOutputStream;
import cpabe.AbePrivateKey;
import cpabe.AbePublicKey;
import cpabe.bsw07.Bsw07Polynomial;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class Bsw07PolicyParentNode extends Bsw07PolicyAbstractNode {
    private int threshold;
    private ArrayList<Bsw07PolicyAbstractNode> children;
    private ArrayList<Integer> satl;
    private Bsw07Polynomial poly;

    public Bsw07PolicyParentNode(int threshold, int numberOfChildren) {
        this.threshold = threshold;
        children = new ArrayList<Bsw07PolicyAbstractNode>(numberOfChildren);
    }

    private static Element evalPoly(Bsw07Polynomial q, Element x) {
        Element r = x.duplicate().setToZero();
        Element t = x.duplicate().setToOne();
        for (Element coeff : q.coef) {
            r.add(coeff.duplicate().mul(t));
            t.mul(x);
        }
        return r;
    }

    private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
        Element t = r.duplicate();
        r.setToOne();
        for (Integer j : s) {
            if (j == i) continue;
            t.set(-j);
            r.mul(t); /* num_muls++; */
            t.set(i - j).invert();
            r.mul(t); /* num_muls++; */
        }
    }

    public boolean addChild(Bsw07PolicyAbstractNode child) {
        return children.add(child);
    }

    public boolean addAllChildren(List<Bsw07PolicyAbstractNode> newChildren) {
        return children.addAll(newChildren);
    }

    public int getThreshold() {
        return threshold;
    }

    public List<Bsw07PolicyAbstractNode> getChildren() {
        return children;
    }

    @Override
    public void writeToStream(AbeOutputStream stream) throws IOException {
        stream.writeInt(getThreshold());
        stream.writeInt(children.size());
        for (Bsw07PolicyAbstractNode child : children) {
            child.writeToStream(stream);
        }
    }

    @Override
    public void fillPolicy(AbePublicKey pub, Element e) {
        poly = Bsw07Polynomial.createRandom(getThreshold() - 1, e);
        for (int i = 0; i < children.size(); i++) {
            Element r = pub.getPairing().getZr().newElement(i + 1);
            Element t = evalPoly(poly, r);
            children.get(i).fillPolicy(pub, t);
        }
    }

    @Override
    protected boolean checkSatisfySpecific(AbePrivateKey prv) {
        boolean canSatisfy = false;
        int cnt = 0;
        for (Bsw07PolicyAbstractNode child : children)
            if (child.checkSatisfy(prv)) cnt++;
        if (cnt >= getThreshold()) canSatisfy = true;
        return canSatisfy;
    }

    @Override
    public void pickSatisfyMinLeaves(AbePrivateKey prv) {
        for (Bsw07PolicyAbstractNode child : children)
            if (child.satisfiable) child.pickSatisfyMinLeaves(prv);

        int len = children.size();
        ArrayList<Integer> c = new ArrayList<Integer>(len);
        for (int i = 0; i < len; i++)
            c.add(new Integer(i));
        Collections.sort(c, new IntegerComparator(this));

        satl = new ArrayList<Integer>();
        minLeaves = 0;
        int l = 0;
        for (int i = 0; i < len && l < getThreshold(); i++) {
            int c_i = c.get(i).intValue(); /* c[i] */
            Bsw07PolicyAbstractNode curChild = children.get(c_i);
            if (curChild.satisfiable) {
                l++;
                minLeaves += curChild.minLeaves;
                satl.add(new Integer(c_i + 1));
            }
        }
    }

    @Override
    protected void decFlattenSpecific(Element r, Element exp, AbePrivateKey prv) {
        Element t = prv.getPublicKey().getPairing().getZr().newElement();
        for (Integer cur : satl) {
            lagrangeCoef(t, satl, cur.intValue());
            Element expnew = exp.duplicate().mul(t);
            children.get(cur - 1).decFlattenSpecific(r, expnew, prv);
        }
    }

    private static class IntegerComparator implements Comparator<Integer> {
        private Bsw07PolicyParentNode policy;

        public IntegerComparator(Bsw07PolicyParentNode p) {
            this.policy = p;
        }

        @Override
        public int compare(Integer o1, Integer o2) {
            int k = policy.children.get(o1).minLeaves;
            int l = policy.children.get(o2).minLeaves;
            return k < l ? -1 : (k == l ? 0 : 1);
        }
    }
}
