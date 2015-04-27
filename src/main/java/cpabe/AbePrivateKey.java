package cpabe;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import cpabe.bsw07.Bsw07PrivateKeyComponent;
import it.unisa.dia.gas.jpbc.Element;

public class AbePrivateKey {
    /*
     * A private key
     */
    /** G2 **/
    Element                             d;
    ArrayList<Bsw07PrivateKeyComponent> components;
    AbePublicKey                  pubKey;

    public AbePrivateKey(Element d, ArrayList<Bsw07PrivateKeyComponent> components, AbePublicKey pubKey) {
        this.d = d;
        this.components = components;
        this.pubKey = pubKey;
    }

    public AbePublicKey getPublicKey() {
        return pubKey;
    }

    /**
     * @return a new privatekey, where d and the component list has been duplicated. The list elements have NOT been duplicated.
     */
    public AbePrivateKey duplicate() {
        ArrayList<Bsw07PrivateKeyComponent> duplicatedComponents = new ArrayList<Bsw07PrivateKeyComponent>(components.size());
        for (Bsw07PrivateKeyComponent cur : components) {
            // should each component also be duplicated? only necessary if components are altered somewhere, which they are not
            duplicatedComponents.add(cur);
        }
        return new AbePrivateKey(d.duplicate(), duplicatedComponents, pubKey);
    }

    public Element getD() {
        return d;
    }
    
    public List<Bsw07PrivateKeyComponent> getComponents() {
    	return components;
    }
    
    public Bsw07PrivateKeyComponent getSatisfyingComponent(Element hashedAttribute) {
        for (int i = 0; i < components.size(); i++) {
            Bsw07PrivateKeyComponent component = components.get(i);
            if (component.hashedAttribute.isEqual(hashedAttribute)) {
                return component;
            }
        }
        return null;
    }
    
    public AbePrivateKey newKeyWithAddedAttributes(List<Bsw07PrivateKeyComponent> newComponents) {
        AbePrivateKey newKey = this.duplicate();
        newKey.components.addAll(newComponents);
        return newKey;
    }

    public static AbePrivateKey readFromFile(File file) throws IOException {
    	try (FileInputStream fis = new FileInputStream(file)) {
    		return readFromStream(fis);
    	}
    }
    
    public static AbePrivateKey readFromStream(InputStream stream) throws IOException {
    	AbeInputStream abeStream = new AbeInputStream(stream);
        AbePublicKey pubKey = AbePublicKey.readFromStream(abeStream);
        abeStream.setPublicKey(pubKey);
        Element d = abeStream.readElement();
        int compsLength = abeStream.readInt();
        ArrayList<Bsw07PrivateKeyComponent> components = new ArrayList<Bsw07PrivateKeyComponent>(compsLength);

        for (int i = 0; i < compsLength; i++) {
            Element hashedAttribute = abeStream.readElement();
            Element comp_d = abeStream.readElement();
            Element comp_dp = abeStream.readElement();
            components.add(new Bsw07PrivateKeyComponent(hashedAttribute, comp_d, comp_dp));
        }
        return new AbePrivateKey(d, components, pubKey);
    }
    
    public void writeToStream(OutputStream stream) throws IOException {
    	AbeOutputStream abeStream = new AbeOutputStream(stream, pubKey);
    	pubKey.writeToStream(abeStream);
    	abeStream.writeElement(d);
        int compsLength = components.size();
        abeStream.writeInt(compsLength);
        for (int i = 0; i < compsLength; i++) {
            Bsw07PrivateKeyComponent cur = components.get(i);
            abeStream.writeElement(cur.hashedAttribute);
            abeStream.writeElement(cur.d);
            abeStream.writeElement(cur.dp);
        }
    }
    
    public void writeToFile(File file) throws IOException {
    	try (FileOutputStream fos = new FileOutputStream(file)) {
    		writeToStream(fos);
    	}
    }
}