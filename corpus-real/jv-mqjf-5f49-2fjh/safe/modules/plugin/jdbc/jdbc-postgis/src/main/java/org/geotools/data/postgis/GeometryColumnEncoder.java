















package org.geotools.data.postgis;

import org.geotools.api.feature.type.GeometryDescriptor;
import org.geotools.jdbc.JDBCDataStore;
import org.geotools.util.Version;

public class GeometryColumnEncoder {

    private final boolean atLeast2_2_0;
    private final boolean stSimplifyEnabled;
    private final boolean stPreserveTopologyEnabled;
    private final boolean encodeBase64;
    private final PostGISDialect dialect;

    GeometryColumnEncoder(
            Version version,
            boolean stSimplifyEnabled,
            boolean stPreserveTopologyEnabled,
            boolean encodeBase64,
            PostGISDialect dialect) {



        this.atLeast2_2_0 = version != null && version.compareTo(PostGISDialect.V_2_2_0) >= 0;
        this.stSimplifyEnabled = stSimplifyEnabled;
        this.stPreserveTopologyEnabled = stPreserveTopologyEnabled;
        this.encodeBase64 = encodeBase64;
        this.dialect = dialect;
    }

    public void encode(GeometryDescriptor gatt, String prefix, StringBuffer sql, boolean force2D, Double distance) {

        if (encodeBase64) {
            sql.append("encode(");
        }

        if (distance == null) {
            encodeNotSimplified(gatt, prefix, sql, force2D);
        } else {
            encodeSimplified(gatt, prefix, sql, force2D, distance);
        }

        if (encodeBase64) {
            sql.append(", 'base64')");
        }
    }

    private void encodeNotSimplified(GeometryDescriptor gatt, String prefix, StringBuffer sql, boolean force2D) {

        boolean geography = "geography".equals(gatt.getUserData().get(JDBCDataStore.JDBC_NATIVE_TYPENAME));
        if (geography) {
            encodeGeography(gatt, prefix, sql);
        } else {
            if (force2D) {
                sql.append("ST_AsBinary(").append(dialect.getForce2DFunction()).append("(");
                dialect.encodeColumnName(prefix, gatt.getLocalName(), sql);
                sql.append("))");
            } else {
                sql.append("ST_AsEWKB(");
                dialect.encodeColumnName(prefix, gatt.getLocalName(), sql);
                sql.append(")");
            }
        }
    }

    private void encodeGeography(GeometryDescriptor gatt, String prefix, StringBuffer sql) {
        sql.append("ST_AsBinary(");
        dialect.encodeColumnName(prefix, gatt.getLocalName(), sql);
        sql.append(")");
    }

    private void encodeSimplified(
            GeometryDescriptor gatt, String prefix, StringBuffer sql, boolean force2D, double distance) {
        boolean geography = "geography".equals(gatt.getUserData().get(JDBCDataStore.JDBC_NATIVE_TYPENAME));

        if (geography) {
            encodeGeography(gatt, prefix, sql);
            return;
        }

        if (dialect.isStraightSegmentsGeometry(gatt)) {
            if (atLeast2_2_0) {
                sql.append("ST_AsTWKB(");
                encode2DGeometry(gatt, prefix, sql, stSimplifyEnabled ? distance : null);
                sql.append("," + getTWKBDigits(distance) + ")");
            } else {
                sql.append("ST_AsBinary(");
                encode2DGeometry(gatt, prefix, sql, stSimplifyEnabled ? distance : null);
                sql.append(")");
            }
        } else {

            sql.append("ST_AsBinary(");
            sql.append("CASE WHEN ST_HasArc(");
            dialect.encodeColumnName(prefix, gatt.getLocalName(), sql);
            sql.append(") THEN ");
            dialect.encodeColumnName(prefix, gatt.getLocalName(), sql);
            sql.append(" ELSE ");
            encode2DGeometry(gatt, prefix, sql, distance);
            sql.append(" END)");
        }
    }

    private void encode2DGeometry(GeometryDescriptor gatt, String prefix, StringBuffer sql, Double distance) {
        if (distance != null) {
            if (stPreserveTopologyEnabled) {
                sql.append("ST_SimplifyPreserveTopology(");
            } else {
                sql.append("ST_Simplify(");
            }
        }

        sql.append(dialect.getForce2DFunction() + "(");
        dialect.encodeColumnName(prefix, gatt.getLocalName(), sql);
        sql.append(")");

        if (distance != null) {
            String preserveCollapsed = atLeast2_2_0 && !stPreserveTopologyEnabled ? ", true" : "";
            sql.append(", " + distance + preserveCollapsed + ")");
        }
    }


    private int getTWKBDigits(Double distance) {
        if (distance.doubleValue() == 0D) {
            return 7;
        }
        int result = -(int) Math.floor(Math.log10(distance));


        if (result > 7) {
            result = 7;
        } else if (result < -7) {
            result = -7;
        }
        return result;
    }
}
