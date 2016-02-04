package cpabe;

import java.io.IOException;
import java.util.Arrays;

public class Version {
    public final static int MAJOR_VERSION = 1;
    public final static int MINOR_VERSION = 0;
    public final static byte[] MAGIC_BYTES = {'J', 'C', 'P', 'A', 'B', 'E'};

    public static void readAndVerify(AbeInputStream inputStream) throws IOException {
        byte[] magicBytes = new byte[MAGIC_BYTES.length];
        inputStream.readFully(magicBytes);
        if (!Arrays.equals(magicBytes, MAGIC_BYTES))
            throw new IOException("Invalid magic bytes: probably not a JCPABE file");
        int majorVersion = inputStream.readInt();
        int minorVersion = inputStream.readInt();
        if (majorVersion != MAJOR_VERSION || minorVersion != MINOR_VERSION)
            throw new IOException("Unsupported version of ABE files");
    }

    public static void writeToStream(AbeOutputStream outputStream) throws IOException {
        outputStream.write(MAGIC_BYTES);
        outputStream.writeInt(MAJOR_VERSION);
        outputStream.writeInt(MINOR_VERSION);
    }
}
