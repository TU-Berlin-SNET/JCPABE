package cpabe.bsw07;

import it.unisa.dia.gas.jpbc.Element;

public class Bsw07Polynomial {
    /* coefficients from [0] x^0 to [deg] x^deg */
    public Element[] coef; /* G_T (of length deg+1) */

    private Bsw07Polynomial(int deg) {
        coef = new Element[deg + 1];
    }

    /**
     * Generates a new polynomial with random coefficients of the element type given as zeroVal. The 0th coefficient has the same
     * value as zeroVal.
     *
     * @param deg     number of coefficients
     * @param zeroVal
     */
    public static Bsw07Polynomial createRandom(int deg, Element zeroVal) {
        Bsw07Polynomial newPoly = new Bsw07Polynomial(deg);
        for (int i = 0; i < newPoly.coef.length; i++)
            newPoly.coef[i] = zeroVal.duplicate();

        newPoly.coef[0].set(zeroVal);

        for (int i = 1; i < newPoly.coef.length; i++)
            newPoly.coef[i].setToRandom();
        return newPoly;
    }

}
