package cpabe.bsw07;

import cpabe.*;
import cpabe.bsw07.policy.Bsw07PolicyAbstractNode;
import cpabe.bsw07.policy.Bsw07PolicyLeafNode;
import cpabe.bsw07.policy.Bsw07PolicyParentNode;
import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

public class Bsw07 {

    private static final String ATTRIBUTE_NOT_FOUND = "an attribute was not found in the source private key";
    private static final String ATTRIBUTES_DONT_SATISFY = "decryption failed: attributes in key do not satisfy policy";

    /**
     * Generate a secret master key. The public master key is part of the secret master key.
     */
    public static AbeSecretMasterKey setup() {
        AbePublicKey pub = new AbePublicKey(AbeSettings.curveParams);
        Element g = pub.getPairing().getG1().newRandomElement();
        Element alpha = pub.getPairing().getZr().newRandomElement();
        Element beta = pub.getPairing().getZr().newRandomElement();
        Element beta_inv = beta.duplicate().invert();

        Element h = g.duplicate().powZn(beta);
        Element f = g.duplicate().powZn(beta_inv);
        Element g_hat_alpha = g.duplicate().powZn(alpha);
        Element e_g_g_hat_alpha = pub.getPairing().pairing(g, g_hat_alpha);
        pub.setElements(g, h, f, e_g_g_hat_alpha);
        return new AbeSecretMasterKey(pub, beta, g_hat_alpha);
    }

    /**
     * Generate a private key with the given set of attributes (internal representation of attributes).
     */
    public static AbePrivateKey keygen(AbeSecretMasterKey msk, String[] attributes) {
        Element r = msk.getPublicKey().getPairing().getZr().newRandomElement();
        Element g_r = msk.getPublicKey().g.duplicate().powZn(r);
        ArrayList<Bsw07PrivateKeyComponent> components = generatePrivateKeyComponents(msk.getPublicKey(), g_r, attributes);
        Element beta_inv = msk.beta.duplicate().invert();
        Element prv_d = msk.g_alpha.duplicate().mul(g_r).powZn(beta_inv);
        return new AbePrivateKey(prv_d, components, msk.getPublicKey());
    }

    private static ArrayList<Bsw07PrivateKeyComponent> generatePrivateKeyComponents(AbePublicKey pub, Element g_r, String[] attributes) {
        ArrayList<Bsw07PrivateKeyComponent> components = new ArrayList<Bsw07PrivateKeyComponent>(attributes.length);
        for (String attribute : attributes) {
            Element hashedAttribute = Bsw07Util.elementG2FromString(attribute, pub);
            Element rp = pub.getPairing().getZr().newRandomElement();
            Element h_rp = hashedAttribute.duplicate().powZn(rp);
            Element comp_d = g_r.duplicate().mul(h_rp);
            Element comp_dp = pub.g.duplicate().powZn(rp);
            components.add(new Bsw07PrivateKeyComponent(hashedAttribute, comp_d, comp_dp));
        }
        return components;
    }

    /**
     * Generates additional attributes for a given value priv_d, which should come from a private key. The private key needs to
     * have been generated with the same master key as msk. The private key components returned by this method can be added to a
     * private key, thus adding the given attributes to the private key.
     *
     * @param msk
     * @param priv_d
     * @param newAttributes
     * @return
     */
    public static ArrayList<Bsw07PrivateKeyComponent> generateAdditionalAttributes(AbeSecretMasterKey msk, Element priv_d, String[] newAttributes) {
        Element g_r = priv_d.duplicate().powZn(msk.beta).div(msk.g_alpha);
        return generatePrivateKeyComponents(msk.getPublicKey(), g_r, newAttributes);
    }

    /**
     * Creates a new private key from an existing private key with a subset of the attributes.
     */
    public static AbePrivateKey delegate(AbePrivateKey oldPrivateKey, String[] attributesSubset) throws IllegalArgumentException {
        Element rt = oldPrivateKey.getPublicKey().getPairing().getZr().newRandomElement();
        Element g_rt = oldPrivateKey.getPublicKey().g.duplicate().powZn(rt);

        ArrayList<Bsw07PrivateKeyComponent> prv_comps = new ArrayList<Bsw07PrivateKeyComponent>(attributesSubset.length);
        for (String curAttribute : attributesSubset) {
            Element hashed_compAttribute = Bsw07Util.elementG2FromString(curAttribute, oldPrivateKey.getPublicKey());

            Bsw07PrivateKeyComponent componentSource = oldPrivateKey.getSatisfyingComponent(hashed_compAttribute);
            if (componentSource == null) {
                throw new IllegalArgumentException(ATTRIBUTE_NOT_FOUND);
            }
            Element rtp = oldPrivateKey.getPublicKey().getPairing().getZr().newRandomElement();
            Element h_rtp = hashed_compAttribute.duplicate().powZn(rtp);

            Element comp_d = g_rt.duplicate().mul(h_rtp).mul(componentSource.d);
            Element comp_dp = oldPrivateKey.getPublicKey().g.duplicate().powZn(rtp).mul(componentSource.dp);
            prv_comps.add(new Bsw07PrivateKeyComponent(hashed_compAttribute, comp_d, comp_dp));
        }
        Element f_at_rt = oldPrivateKey.getPublicKey().f.duplicate().powZn(rt);
        Element prv_d = oldPrivateKey.getD().duplicate().mul(f_at_rt);
        return new AbePrivateKey(prv_d, prv_comps, oldPrivateKey.getPublicKey());
    }

    /**
     * Pick a random group element and encrypt it under the specified access policy. The resulting ciphertext is returned.
     * <p/>
     * After using this function, it is normal to extract the random data in m using the pbc functions element_length_in_bytes and
     * element_to_bytes and use it as a key for hybrid encryption.
     * <p/>
     * The policy is specified as a simple string which encodes a postorder traversal of threshold tree defining the access
     * policy. As an example,
     * <p/>
     * "foo bar fim 2of3 baf 1of2"
     * <p/>
     * specifies a policy with two threshold gates and four leaves. It is not possible to specify an attribute with whitespace in
     * it (although "_" is allowed)
     */
    public static Bsw07CipherAndKey encrypt(AbePublicKey pub, String policy) throws AbeEncryptionException {
        Bsw07PolicyAbstractNode policyTree = Bsw07PolicyAbstractNode.parsePolicy(policy, pub);
        return encrypt(pub, policyTree);
    }

    public static Bsw07CipherAndKey encrypt(AbePublicKey pub, Bsw07PolicyAbstractNode policyTree) {
        Element s = pub.getPairing().getZr().newRandomElement();
        Element message = pub.getPairing().getGT().newRandomElement();
        Element cs = pub.e_g_g_hat_alpha.duplicate().powZn(s).mul(message);
        Element c = pub.h.duplicate().powZn(s);
        policyTree.fillPolicy(pub, s);
        return new Bsw07CipherAndKey(new Bsw07Cipher(policyTree, cs, c), message);
    }

    /**
     * Decrypt the specified ciphertext using the given private key, return the decrypted element m.
     * <p/>
     * Throws an exception if decryption was not possible.
     */
    public static Element decrypt(AbePrivateKey privateKey, Bsw07Cipher cipher) throws AbeDecryptionException {
        if (!canDecrypt(privateKey, cipher)) {
            throw new AbeDecryptionException(ATTRIBUTES_DONT_SATISFY);
        }
        cipher.policyTree.pickSatisfyMinLeaves(privateKey);
        Element t = privateKey.getPublicKey().getPairing().getGT().newElement();
        cipher.policyTree.decFlatten(t, privateKey);
        Element m = cipher.getCs().duplicate();
        m.mul(t); /* num_muls++; */
        t = privateKey.getPublicKey().getPairing().pairing(cipher.getC(), privateKey.getD()).invert();
        return m.mul(t); /* num_muls++; */
    }

    public static boolean canDecrypt(AbePrivateKey prv, Bsw07Cipher cph) {
        return cph.policyTree.isSatisfiable(prv);
    }

    public static ArrayList<Bsw07PrivateKeyComponent> generateAdditionalAttributes(AbeSecretMasterKey msk, Element priv_d, List<Element> newHashedAttributes) {
        Element g_r = priv_d.duplicate().powZn(msk.beta).div(msk.g_alpha);
        ArrayList<Bsw07PrivateKeyComponent> components = new ArrayList<Bsw07PrivateKeyComponent>(newHashedAttributes.size());
        for (Element hashedAttribute : newHashedAttributes) {
            Element rp = msk.getPublicKey().getPairing().getZr().newRandomElement();
            Element h_rp = hashedAttribute.duplicate().powZn(rp);
            Element comp_d = g_r.duplicate().mul(h_rp);
            Element comp_dp = msk.getPublicKey().g.duplicate().powZn(rp);
            components.add(new Bsw07PrivateKeyComponent(hashedAttribute, comp_d, comp_dp));
        }
        return components;
    }

    /**
     * Creates a private key that fulfills all attributes of the given cipher.
     *
     * @param secretKey
     * @param cph
     * @return
     * @throws AbeDecryptionException
     */
    public static AbePrivateKey keygen(AbeSecretMasterKey secretKey, Bsw07Cipher cph) {
        AbePrivateKey emptyKey = keygen(secretKey, new String[]{});

        List<Element> hashedAttributes = new ArrayList<Element>();
        ArrayList<Bsw07PolicyAbstractNode> curNodes = new ArrayList<Bsw07PolicyAbstractNode>();
        curNodes.add(cph.policyTree);

        while (!curNodes.isEmpty()) {
            Bsw07PolicyAbstractNode curNode = curNodes.remove(0);
            if (curNode instanceof Bsw07PolicyLeafNode) {
                hashedAttributes.add(((Bsw07PolicyLeafNode) curNode).getHashedAttribute());
            } else { // is ParentNode
                curNodes.addAll(((Bsw07PolicyParentNode) curNode).getChildren());
            }
        }

        AbePrivateKey filledKey = emptyKey.newKeyWithAddedAttributes(generateAdditionalAttributes(secretKey, emptyKey.getD(), hashedAttributes));
        return filledKey;
    }
}
