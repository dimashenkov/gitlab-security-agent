

















package org.geotools.data.postgis;

import java.io.IOException;
import org.locationtech.jts.io.InStream;






public class VarintDataInStream {

    InStream stream;
    private byte[] buf1 = new byte[1];


    public VarintDataInStream() {}


    public VarintDataInStream(InStream stream) {
        this.stream = stream;
    }


    public void setInStream(InStream stream) {
        this.stream = stream;
    }


    public byte readByte() throws IOException {
        stream.read(buf1);
        return buf1[0];
    }


    public int readUnsignedInt() throws IOException {

        stream.read(buf1);
        byte b = buf1[0];
        if ((b & 0x80) == 0) {
            return b;
        }


        int val = b & 0x7f;
        int shift = 7;
        for (; shift < 32; shift += 7) {
            stream.read(buf1);
            b = buf1[0];
            val = val | (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                return val;
            }
        }

        for (; shift < 64; shift += 7) {
            stream.read(buf1);
            b = buf1[0];
            if ((b & 0x80) == 0) {
                return val;
            }
        }

        throw new IllegalArgumentException("Invalid varint found, used more than 64 bits");
    }


    public int readSignedInt() throws IOException {
        int val = readUnsignedInt();
        return unzigzag(val);
    }

    private int unzigzag(int n) {
        return n >>> 1 ^ -(n & 1);
    }


    long readUnsignedLong() throws IOException {
        long result = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            stream.read(buf1);
            byte b = buf1[0];
            result |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
        }
        throw new IllegalArgumentException("Invalid varint found, used more than 64 bits");
    }


    public long readSignedLong() throws IOException {
        long val = readUnsignedLong();
        return unzigzagLong(val);
    }

    private long unzigzagLong(long n) {
        return n >>> 1 ^ -(n & 1);
    }
}
