package cpabe.policyparser;

public class ASTOf extends SimpleNode {
    private int number;

    public ASTOf(int id) {
        super(id);
    }

    public ASTOf(ParseTree p, int id) {
        super(p, id);
    }

    public int getNumber() {
        return number;
    }

    public void setNumber(String numberString) {
        this.number = Integer.parseInt(numberString);
    }

    public String toString() {
        return "Of: " + number;
    }
}
