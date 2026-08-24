
















package org.geotools.data.postgis;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import org.geotools.api.data.DataSourceException;
import org.geotools.geometry.jts.WKBReader;
import org.geotools.util.Base64;
import org.locationtech.jts.geom.Geometry;
import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.io.ByteArrayInStream;
import org.locationtech.jts.io.WKBWriter;







public class WKBAttributeIO {
    WKBReader wkbr;
    ByteArrayInStream inStream = new ByteArrayInStream(new byte[0]);
    GeometryFactory gf;
    boolean base64EncodingEnabled = true;

    public WKBAttributeIO() {
        this(new GeometryFactory());
    }

    public WKBAttributeIO(GeometryFactory gf) {
        wkbr = new WKBReader(gf);
        this.gf = gf;
    }

    public void setGeometryFactory(GeometryFactory gf) {
        if (gf != this.gf) {
            this.gf = gf;
            wkbr = new WKBReader(gf);
        }
    }

    public boolean isBase64EncodingEnabled() {
        return base64EncodingEnabled;
    }

    public void setBase64EncodingEnabled(boolean base64EncodingEnabled) {
        this.base64EncodingEnabled = base64EncodingEnabled;
    }









    private Geometry wkb2Geometry(byte[] wkbBytes) throws IOException {
        if (wkbBytes == null)


            return null;
        try {
            inStream.setBytes(wkbBytes);
            return wkbr.read(inStream);
        } catch (Exception e) {
            throw new DataSourceException("An exception occurred while parsing WKB data", e);
        }
    }


    public Object read(ResultSet rs, String columnName) throws IOException {
        try {
            byte[] bytes = rs.getBytes(columnName);
            if (bytes == null)
            return null;
            if (base64EncodingEnabled) {
                bytes = Base64.decode(bytes);
            }
            return wkb2Geometry(bytes);
        } catch (SQLException e) {
            throw new DataSourceException("SQL exception occurred while reading the geometry.", e);
        }
    }


    public Object read(ResultSet rs, int columnIndex) throws IOException {
        try {
            byte[] bytes = rs.getBytes(columnIndex);
            if (bytes == null)
            return null;
            if (base64EncodingEnabled) {
                bytes = Base64.decode(bytes);
            }
            return wkb2Geometry(bytes);
        } catch (SQLException e) {
            throw new DataSourceException("SQL exception occurred while reading the geometry.", e);
        }
    }


    public void write(PreparedStatement ps, int position, Object value) throws IOException {
        try {
            if (value == null) {
                ps.setNull(position, Types.OTHER);
            } else {
                ps.setBytes(position, new WKBWriter().write((Geometry) value));
            }
        } catch (SQLException e) {
            throw new DataSourceException("SQL exception occurred while reading the geometry.", e);
        }
    }


    public static byte getFromChar(char c) {
        if (c <= '9') {
            return (byte) (c - '0');
        } else if (c <= 'F') {
            return (byte) (c - 'A' + 10);
        } else {
            return (byte) (c - 'a' + 10);
        }
    }
}
