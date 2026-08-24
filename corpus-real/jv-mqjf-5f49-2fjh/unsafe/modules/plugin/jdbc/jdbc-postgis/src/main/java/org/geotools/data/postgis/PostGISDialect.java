















package org.geotools.data.postgis;

import static java.util.Map.entry;

import java.io.IOException;
import java.lang.reflect.Array;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import org.geotools.api.feature.simple.SimpleFeatureType;
import org.geotools.api.feature.type.AttributeDescriptor;
import org.geotools.api.feature.type.GeometryDescriptor;
import org.geotools.api.filter.Filter;
import org.geotools.api.referencing.FactoryException;
import org.geotools.api.referencing.crs.CoordinateReferenceSystem;
import org.geotools.data.jdbc.FilterToSQL;
import org.geotools.filter.visitor.JsonPointerFilterSplittingVisitor;
import org.geotools.filter.visitor.PostPreProcessFilterSplittingVisitor;
import org.geotools.geometry.jts.CircularRing;
import org.geotools.geometry.jts.CircularString;
import org.geotools.geometry.jts.CompoundCurve;
import org.geotools.geometry.jts.CompoundRing;
import org.geotools.geometry.jts.CurvePolygon;
import org.geotools.geometry.jts.CurvedRing;
import org.geotools.geometry.jts.MultiCurve;
import org.geotools.geometry.jts.MultiSurface;
import org.geotools.geometry.jts.ReferencedEnvelope;
import org.geotools.geometry.jts.WKTWriter2;
import org.geotools.jdbc.BasicSQLDialect;
import org.geotools.jdbc.ColumnMetadata;
import org.geotools.jdbc.JDBCDataStore;
import org.geotools.referencing.CRS;
import org.geotools.util.Version;
import org.geotools.util.factory.Hints;
import org.locationtech.jts.geom.Envelope;
import org.locationtech.jts.geom.Geometry;
import org.locationtech.jts.geom.GeometryCollection;
import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.geom.LineString;
import org.locationtech.jts.geom.LinearRing;
import org.locationtech.jts.geom.MultiLineString;
import org.locationtech.jts.geom.MultiPoint;
import org.locationtech.jts.geom.MultiPolygon;
import org.locationtech.jts.geom.Point;
import org.locationtech.jts.geom.Polygon;
import org.locationtech.jts.io.ParseException;
import org.locationtech.jts.io.WKTReader;
import org.locationtech.jts.io.WKTWriter;
import org.postgresql.jdbc.PgConnection;

public class PostGISDialect extends BasicSQLDialect {

    public static final String BIGDATE_UDT = "bigdate";


    static final Map<String, Class> TYPE_TO_CLASS_MAP = Map.ofEntries(
            entry("GEOMETRY", Geometry.class),
            entry("GEOGRAPHY", Geometry.class),
            entry("POINT", Point.class),
            entry("POINTM", Point.class),
            entry("LINESTRING", LineString.class),
            entry("LINESTRINGM", LineString.class),
            entry("POLYGON", Polygon.class),
            entry("POLYGONM", Polygon.class),
            entry("MULTIPOINT", MultiPoint.class),
            entry("MULTIPOINTM", MultiPoint.class),
            entry("MULTILINESTRING", MultiLineString.class),
            entry("MULTILINESTRINGM", MultiLineString.class),
            entry("MULTIPOLYGON", MultiPolygon.class),
            entry("MULTIPOLYGONM", MultiPolygon.class),
            entry("GEOMETRYCOLLECTION", GeometryCollection.class),
            entry("GEOMETRYCOLLECTIONM", GeometryCollection.class),
            entry("COMPOUNDCURVE", CompoundCurve.class),
            entry("MULTICURVE", MultiCurve.class),
            entry("CURVEPOLYGON", CurvePolygon.class),
            entry("CIRCULARSTRING", CircularString.class),
            entry("MULTISURFACE", MultiSurface.class),
            entry("BYTEA", byte[].class));


    static final Map<String, Class> SIMPLE_TYPE_TO_CLASS_MAP = Map.ofEntries(
            entry("INT2", Short.class),
            entry("INT4", Integer.class),
            entry("INT8", Long.class),
            entry("FLOAT4", Float.class),
            entry("FLOAT8", Double.class),
            entry("BOOL", Boolean.class),
            entry("VARCHAR", String.class),
            entry("DATE", java.sql.Date.class),
            entry("TIME", java.sql.Time.class),
            entry("TIMESTAMP", java.sql.Timestamp.class),
            entry("TIMESTAMPZ", java.sql.Timestamp.class),
            entry("TIMESTAMPTZ", java.sql.Timestamp.class));




    static final Set<Class> NON_CURVED_GEOMETRY_CLASSES = Set.of(
            Point.class,
            MultiPoint.class,
            LineString.class,
            LinearRing.class,
            MultiLineString.class,
            Polygon.class,
            MultiPolygon.class);


    static final Map<Class, String> CLASS_TO_TYPE_MAP = Map.ofEntries(
            entry(Geometry.class, "GEOMETRY"),
            entry(Point.class, "POINT"),
            entry(LineString.class, "LINESTRING"),
            entry(Polygon.class, "POLYGON"),
            entry(MultiPoint.class, "MULTIPOINT"),
            entry(MultiLineString.class, "MULTILINESTRING"),
            entry(MultiPolygon.class, "MULTIPOLYGON"),
            entry(GeometryCollection.class, "GEOMETRYCOLLECTION"),
            entry(CircularString.class, "CIRCULARSTRING"),
            entry(CircularRing.class, "CIRCULARSTRING"),
            entry(MultiCurve.class, "MULTICURVE"),
            entry(CompoundCurve.class, "COMPOUNDCURVE"),
            entry(CompoundRing.class, "COMPOUNDCURVE"),
            entry(byte[].class, "BYTEA"));

    private GeometryColumnEncoder geometryColumnEncoder;

    @Override
    public boolean isAggregatedSortSupported(String function) {
        return "distinct".equalsIgnoreCase(function);
    }

    static final Version V_1_5_0 = new Version("1.5.0");

    static final Version V_2_0_0 = new Version("2.0.0");

    static final Version V_2_1_0 = new Version("2.1.0");

    static final Version V_2_2_0 = new Version("2.2.0");

    static final Version PGSQL_V_9_0 = new Version("9.0");

    static final Version PGSQL_V_9_1 = new Version("9.1");

    static final Version PGSQL_V_12_0 = new Version("12.0");

    public PostGISDialect(JDBCDataStore dataStore) {
        super(dataStore);
        this.forceLongitudeFirst = true;
    }

    boolean looseBBOXEnabled = false;

    boolean encodeBBOXFilterAsEnvelope = false;

    boolean estimatedExtentsEnabled = false;

    boolean functionEncodingEnabled = false;

    boolean simplifyEnabled = true;

    boolean base64EncodingEnabled = true;

    boolean topologyPreserved = false;


    boolean escapeBackslash = true;

    Version version, pgsqlVersion;

    public boolean isLooseBBOXEnabled() {
        return looseBBOXEnabled;
    }

    public void setLooseBBOXEnabled(boolean looseBBOXEnabled) {
        this.looseBBOXEnabled = looseBBOXEnabled;
    }

    public boolean isEncodeBBOXFilterAsEnvelope() {
        return encodeBBOXFilterAsEnvelope;
    }

    public void setEncodeBBOXFilterAsEnvelope(boolean encodeBBOXFilterAsEnvelope) {
        this.encodeBBOXFilterAsEnvelope = encodeBBOXFilterAsEnvelope;
    }

    public boolean isEstimatedExtentsEnabled() {
        return estimatedExtentsEnabled;
    }

    public void setEstimatedExtentsEnabled(boolean estimatedExtentsEnabled) {
        this.estimatedExtentsEnabled = estimatedExtentsEnabled;
    }

    public boolean isFunctionEncodingEnabled() {
        return functionEncodingEnabled;
    }


    public void setFunctionEncodingEnabled(boolean functionEncodingEnabled) {
        this.functionEncodingEnabled = functionEncodingEnabled;
    }

    public boolean isSimplifyEnabled() {
        return simplifyEnabled;
    }

    public boolean isEscapeBackslash() {
        return escapeBackslash;
    }

    @Override
    public boolean canSimplifyPoints() {

        return version != null && version.compareTo(V_2_2_0) >= 0 && isSimplifyEnabled();
    }




    public void setSimplifyEnabled(boolean simplifyEnabled) {
        this.simplifyEnabled = simplifyEnabled;
    }

    public boolean isTopologyPreserved() {
        return topologyPreserved;
    }







    public void setTopologyPreserved(boolean topologyPreserved) {
        this.topologyPreserved = topologyPreserved;
    }

    @Override
    public void initializeConnection(Connection cx) throws SQLException {
        super.initializeConnection(cx);
        getPostgreSQLVersion(cx);
        getVersion(cx);
        checkStandardConformingStrings(cx);
    }

    @Override
    public boolean includeTable(String schemaName, String tableName, Connection cx) throws SQLException {
        if (tableName.equals("geometry_columns")) {
            return false;
        } else if (tableName.startsWith("spatial_ref_sys")) {
            return false;
        } else if (tableName.equals("geography_columns")) {
            return false;
        } else if (tableName.equals("raster_columns")) {
            return false;
        } else if (tableName.equals("raster_overviews")) {
            return false;
        }

        if (schemaName != null && schemaName.equals("topology")) {
            return false;
        }

        return true;
    }

    ThreadLocal<WKBAttributeIO> wkbReader = new ThreadLocal<>();
    ThreadLocal<TWKBAttributeIO> twkbReader = new ThreadLocal<>();

    @Override
    public Geometry decodeGeometryValue(
            GeometryDescriptor descriptor,
            ResultSet rs,
            String column,
            GeometryFactory factory,
            Connection cx,
            Hints hints)
            throws IOException, SQLException {

        if (isTWKBTransferEnabled(cx, descriptor, hints)) {
            TWKBAttributeIO reader = getTWKBReader(factory);

            Geometry g = (Geometry) reader.read(rs, column, descriptor.getType().getBinding());
            return g;
        } else {
            WKBAttributeIO reader = getWKBReader(factory);

            return (Geometry) reader.read(rs, column);
        }
    }

    @Override
    public Geometry decodeGeometryValue(
            GeometryDescriptor descriptor,
            ResultSet rs,
            int column,
            GeometryFactory factory,
            Connection cx,
            Hints hints)
            throws IOException, SQLException {

        if (isTWKBTransferEnabled(cx, descriptor, hints)) {
            TWKBAttributeIO reader = getTWKBReader(factory);

            Geometry g = (Geometry) reader.read(rs, column, descriptor.getType().getBinding());
            return g;
        } else {
            WKBAttributeIO reader = getWKBReader(factory);

            return (Geometry) reader.read(rs, column);
        }
    }

    private boolean isTWKBTransferEnabled(Connection cx, GeometryDescriptor descriptor, Hints hints)
            throws SQLException {
        Double distance = (Double) hints.get(Hints.GEOMETRY_SIMPLIFICATION);
        return isTWKBTransferEnabled(cx, descriptor, distance);
    }

    private boolean isTWKBTransferEnabled(Connection cx, GeometryDescriptor descriptor, Double distance)
            throws SQLException {
        boolean geography = "geography".equals(descriptor.getUserData().get(JDBCDataStore.JDBC_NATIVE_TYPENAME));
        return !geography
                && distance != null
                && getVersion(cx).compareTo(V_2_2_0) >= 0
                && isStraightSegmentsGeometry(descriptor);
    }

    private WKBAttributeIO getWKBReader(GeometryFactory factory) {
        WKBAttributeIO reader = wkbReader.get();
        if (reader == null) {
            reader = new WKBAttributeIO(factory);
            reader.setBase64EncodingEnabled(base64EncodingEnabled);
            wkbReader.set(reader);
        } else {
            reader.setGeometryFactory(factory);
        }
        return reader;
    }

    private TWKBAttributeIO getTWKBReader(GeometryFactory factory) {
        TWKBAttributeIO reader = twkbReader.get();
        if (reader == null) {
            reader = new TWKBAttributeIO(factory);
            reader.setBase64EncodingEnabled(base64EncodingEnabled);
            twkbReader.set(reader);
        } else {
            reader.setGeometryFactory(factory);
        }
        return reader;
    }

    private GeometryColumnEncoder getGeometryColumnEncoder() {


        if (this.geometryColumnEncoder == null) {
            this.geometryColumnEncoder = new GeometryColumnEncoder(
                    this.version, isSimplifyEnabled(), isTopologyPreserved(), base64EncodingEnabled, this);
        }
        return geometryColumnEncoder;
    }

    @Override
    public void encodeGeometryColumn(GeometryDescriptor gatt, String prefix, int srid, Hints hints, StringBuffer sql) {
        boolean force2D = hints != null
                && hints.containsKey(Hints.FEATURE_2D)
                && Boolean.TRUE.equals(hints.get(Hints.FEATURE_2D));
        getGeometryColumnEncoder().encode(gatt, prefix, sql, force2D, null);
    }

    @Override
    public void encodeGeometryColumnSimplified(
            GeometryDescriptor gatt, String prefix, int srid, StringBuffer sql, Double distance) {
        getGeometryColumnEncoder().encode(gatt, prefix, sql, true, distance);
    }

    protected boolean isStraightSegmentsGeometry(GeometryDescriptor gatt) {
        return NON_CURVED_GEOMETRY_CLASSES.contains(gatt.getType().getBinding());
    }

    @Override
    public void encodeGeometryEnvelope(String tableName, String geometryColumn, StringBuffer sql) {
        sql.append("ST_AsText(" + getForce2DFunction() + "(ST_Envelope(");
        sql.append("ST_Extent(" + escapeName(geometryColumn) + "::geometry))))");
    }

    @Override
    public List<ReferencedEnvelope> getOptimizedBounds(String schema, SimpleFeatureType featureType, Connection cx)
            throws SQLException, IOException {
        if (!estimatedExtentsEnabled) return null;

        String tableName = featureType.getTypeName();
        if (dataStore.getVirtualTables().get(tableName) != null) {
            return null;
        }

        Statement st = null;
        ResultSet rs = null;

        List<ReferencedEnvelope> result = new ArrayList<>();
        Savepoint savePoint = null;
        try {
            st = cx.createStatement();
            if (!cx.getAutoCommit()) {
                savePoint = cx.setSavepoint();
            }

            for (AttributeDescriptor att : featureType.getAttributeDescriptors()) {
                if (att instanceof GeometryDescriptor) {

                    StringBuffer sql = new StringBuffer();
                    sql.append("select ST_AsText("
                            + getForce2DFunction()
                            + "(ST_Envelope("
                            + getEstimatedExtentFunction()
                            + "('");
                    if (schema != null) {
                        sql.append(schema);
                        sql.append("', '");
                    }
                    sql.append(tableName);
                    sql.append("', '");
                    sql.append(att.getName().getLocalPart());
                    sql.append("'))))");
                    rs = st.executeQuery(sql.toString());

                    if (rs.next()) {

                        Envelope env = decodeGeometryEnvelope(rs, 1, cx);


                        if (!env.isNull()) {
                            CoordinateReferenceSystem flatCRS =
                                    CRS.getHorizontalCRS(featureType.getCoordinateReferenceSystem());
                            result.add(new ReferencedEnvelope(env, flatCRS));
                        }
                    }
                    rs.close();
                }
            }
        } catch (SQLException e) {
            if (savePoint != null) {
                cx.rollback(savePoint);
            }
            LOGGER.log(
                    Level.WARNING,
                    "Failed to use " + getEstimatedExtentFunction() + ", falling back on envelope aggregation",
                    e);
            return null;
        } finally {
            if (savePoint != null) {
                cx.releaseSavepoint(savePoint);
            }
            dataStore.closeSafe(rs);
            dataStore.closeSafe(st);
        }
        return result;
    }

    @Override
    public Envelope decodeGeometryEnvelope(ResultSet rs, int column, Connection cx) throws SQLException, IOException {
        try {
            String envelope = rs.getString(column);
            if (envelope != null) return new WKTReader().read(envelope).getEnvelopeInternal();
            else

                return new Envelope();
        } catch (ParseException e) {
            throw (IOException) new IOException("Error occurred parsing the bounds WKT").initCause(e);
        }
    }

    @Override
    public Class<?> getMapping(ResultSet columnMetaData, Connection cx) throws SQLException {

        String typeName = columnMetaData.getString("TYPE_NAME");
        int dataType = columnMetaData.getInt("DATA_TYPE");

        if (dataType == Types.ARRAY && typeName.length() > 1) {

            typeName = typeName.substring(1);
            Class<?> arrayContentType = getMappingInternal(columnMetaData, cx, typeName);


            if (arrayContentType == null) {
                arrayContentType = SIMPLE_TYPE_TO_CLASS_MAP.get(typeName.toUpperCase());
            }

            if (arrayContentType != null) {
                try {
                    return Class.forName("[L" + arrayContentType.getName() + ";");
                } catch (ClassNotFoundException e) {
                    LOGGER.log(Level.WARNING, "Failed to create Java equivalent of array class", e);
                    return null;
                }
            }

            return null;
        }

        return getMappingInternal(columnMetaData, cx, typeName);
    }

    private Class<?> getMappingInternal(ResultSet columnMetaData, Connection cx, String typeName) throws SQLException {
        if ("uuid".equalsIgnoreCase(typeName)) {
            return UUID.class;
        }

        if ("citext".equalsIgnoreCase(typeName)) {
            return String.class;
        }

        if (BIGDATE_UDT.equalsIgnoreCase(typeName)) {
            return BigDate.class;
        }

        if (HStore.TYPENAME.equalsIgnoreCase(typeName)) {
            return HStore.class;
        }

        if ("json".equalsIgnoreCase(typeName) || "jsonb".equalsIgnoreCase(typeName)) {
            return String.class;
        }

        String gType = null;
        if ("geometry".equalsIgnoreCase(typeName)) {
            gType = lookupGeometryType(columnMetaData, cx, "geometry_columns", "f_geometry_column");
        } else if ("geography".equalsIgnoreCase(typeName)) {
            gType = lookupGeometryType(columnMetaData, cx, "geography_columns", "f_geography_column");
        } else {
            return null;
        }


        if (gType == null) {

            return Geometry.class;
        } else {
            Class geometryClass = TYPE_TO_CLASS_MAP.get(gType.toUpperCase());
            if (geometryClass == null) {
                geometryClass = Geometry.class;
            }

            return geometryClass;
        }
    }

    String lookupGeometryType(ResultSet columnMetaData, Connection cx, String gTableName, String gColumnName)
            throws SQLException {


        String tableName = columnMetaData.getString("TABLE_NAME");
        String columnName = columnMetaData.getString("COLUMN_NAME");
        String schemaName = columnMetaData.getString("TABLE_SCHEM");


        Statement statement = null;
        ResultSet result = null;

        try {
            String sqlStatement = "SELECT TYPE FROM "
                    + gTableName
                    + " WHERE "
                    + "F_TABLE_SCHEMA = '"
                    + schemaName
                    + "' "
                    + "AND F_TABLE_NAME = '"
                    + tableName
                    + "' "
                    + "AND "
                    + gColumnName
                    + " = '"
                    + columnName
                    + "'";

            LOGGER.log(Level.FINE, "Geometry type check; {0} ", sqlStatement);
            statement = cx.createStatement();
            result = statement.executeQuery(sqlStatement);

            if (result.next()) {
                return result.getString(1);
            }
        } finally {
            dataStore.closeSafe(result);
            dataStore.closeSafe(statement);
        }

        return null;
    }

    @Override
    public void handleUserDefinedType(ResultSet columnMetaData, ColumnMetadata metadata, Connection cx)
            throws SQLException {

        String tableName = columnMetaData.getString("TABLE_NAME");
        String columnName = columnMetaData.getString("COLUMN_NAME");
        String schemaName = columnMetaData.getString("TABLE_SCHEM");

        String sql = "SELECT udt_name FROM information_schema.columns "
                + " WHERE table_schema = '"
                + schemaName
                + "' "
                + "   AND table_name = '"
                + tableName
                + "' "
                + "   AND column_name = '"
                + columnName
                + "' ";
        LOGGER.fine(sql);

        Statement st = cx.createStatement();
        try {
            ResultSet rs = st.executeQuery(sql);
            try {
                if (rs.next()) {
                    metadata.setTypeName(rs.getString(1));
                }
            } finally {
                dataStore.closeSafe(rs);
            }
        } finally {
            dataStore.closeSafe(st);
        }
    }


    @Override
    public CoordinateReferenceSystem createCRS(int srid, Connection cx) throws SQLException {
        if (srid <= 0) {
            return null;
        }
        String sqlStatement = "SELECT AUTH_NAME, AUTH_SRID, SRTEXT FROM SPATIAL_REF_SYS WHERE SRID = " + srid;
        try (Statement statement = cx.createStatement();
                ResultSet result = statement.executeQuery(sqlStatement)) {
            if (!result.next()) {
                LOGGER.warning("SPATIAL_REF_SYS didn't have a row for srid: " + srid);
                return null;
            }
            String code = result.getString(1) + ":" + Integer.toString(result.getInt(2));
            CoordinateReferenceSystem crs = null;
            try {
                crs = CRS.decode(code, true);
            } catch (FactoryException e) {
                LOGGER.log(Level.FINE, "Failed to decode " + code + ".", e);
            }
            if (crs == null) {
                String wkt = result.getString(3);
                try {
                    crs = CRS.parseWKT(wkt);
                } catch (FactoryException e) {
                    LOGGER.log(
                            Level.WARNING,
                            "Failed to parse wkt! " + e.getMessage() + " The problematic WKT is: " + wkt,
                            e);
                }
            }
            return crs;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Failed to retrive information from SPATIAL_REF_SYS for srid: " + srid, e);
        }
        return null;
    }

    @Override
    public Integer getGeometrySRID(String schemaName, String tableName, String columnName, Connection cx)
            throws SQLException {


        Integer srid = null;
        try (Statement statement = cx.createStatement()) {
            if (schemaName == null) schemaName = "public";


            if (supportsGeography(cx)) {

                String sqlStatement = "SELECT SRID FROM GEOGRAPHY_COLUMNS WHERE "
                        + "F_TABLE_SCHEMA = '"
                        + schemaName
                        + "' "
                        + "AND F_TABLE_NAME = '"
                        + tableName
                        + "' "
                        + "AND F_GEOGRAPHY_COLUMN = '"
                        + columnName
                        + "'";
                LOGGER.log(Level.FINE, "Geography srid check; {0} ", sqlStatement);
                try (ResultSet result = statement.executeQuery(sqlStatement)) {

                    if (result.next()) {
                        return 4326;
                    }

                } catch (SQLException e) {
                    LOGGER.log(
                            Level.WARNING,
                            "Failed to retrieve information about "
                                    + schemaName
                                    + "."
                                    + tableName
                                    + "."
                                    + columnName
                                    + " from the geometry_columns table, checking geometry_columns instead",
                            e);
                }
            }



            String sqlStatement = "SELECT SRID FROM GEOMETRY_COLUMNS WHERE "
                    + "F_TABLE_SCHEMA = '"
                    + schemaName
                    + "' "
                    + "AND F_TABLE_NAME = '"
                    + tableName
                    + "' "
                    + "AND F_GEOMETRY_COLUMN = '"
                    + columnName
                    + "'";

            LOGGER.log(Level.FINE, "Geometry srid check; {0} ", sqlStatement);
            try (ResultSet result = statement.executeQuery(sqlStatement)) {

                if (result.next()) {
                    srid = result.getInt(1);
                }
            } catch (SQLException e) {
                LOGGER.log(
                        Level.WARNING,
                        "Failed to retrieve information about "
                                + schemaName
                                + "."
                                + tableName
                                + "."
                                + columnName
                                + " from the geometry_columns table, checking the first geometry instead",
                        e);
            }







            if (srid == null || getVersion(cx).compareTo(V_2_0_0) >= 0 && srid == 0) {
                String sql = "SELECT ST_SRID("
                        + escapeName(columnName)
                        + ") "
                        + "FROM "
                        + escapeName(schemaName)
                        + "."
                        + escapeName(tableName)
                        + " "
                        + "WHERE "
                        + escapeName(columnName)
                        + " IS NOT NULL "
                        + "LIMIT 1";
                try (ResultSet result = statement.executeQuery(sql)) {
                    if (result.next()) {
                        srid = result.getInt(1);
                    }
                }
            }
        }

        return srid;
    }

    @Override
    public int getGeometryDimension(String schemaName, String tableName, String columnName, Connection cx)
            throws SQLException {

        Integer dimension = null;
        try (Statement statement = cx.createStatement()) {
            if (schemaName == null) schemaName = "public";


            if (supportsGeography(cx)) {

                String sqlStatement = "SELECT COORD_DIMENSION FROM GEOGRAPHY_COLUMNS WHERE "
                        + "F_TABLE_SCHEMA = '"
                        + schemaName
                        + "' "
                        + "AND F_TABLE_NAME = '"
                        + tableName
                        + "' "
                        + "AND F_GEOGRAPHY_COLUMN = '"
                        + columnName
                        + "'";
                LOGGER.log(Level.FINE, "Geography srid check; {0} ", sqlStatement);
                try (ResultSet result = statement.executeQuery(sqlStatement)) {

                    if (result.next()) {
                        return result.getInt(1);
                    }
                } catch (SQLException e) {
                    LOGGER.log(
                            Level.WARNING,
                            "Failed to retrieve information about "
                                    + schemaName
                                    + "."
                                    + tableName
                                    + "."
                                    + columnName
                                    + " from the geography_columns table, checking geometry_columns instead",
                            e);
                }
            }


            String sqlStatement = "SELECT COORD_DIMENSION FROM GEOMETRY_COLUMNS WHERE "
                    + "F_TABLE_SCHEMA = '"
                    + schemaName
                    + "' "
                    + "AND F_TABLE_NAME = '"
                    + tableName
                    + "' "
                    + "AND F_GEOMETRY_COLUMN = '"
                    + columnName
                    + "'";

            LOGGER.log(Level.FINE, "Geometry srid check; {0} ", sqlStatement);
            try (ResultSet result = statement.executeQuery(sqlStatement)) {
                if (result.next()) {
                    dimension = result.getInt(1);
                }
            } catch (SQLException e) {
                LOGGER.log(
                        Level.WARNING,
                        "Failed to retrieve information about "
                                + schemaName
                                + "."
                                + tableName
                                + "."
                                + columnName
                                + " from the geometry_columns table, checking the first geometry instead",
                        e);
            }
        }



        if (dimension == null) {
            dimension = getDimensionFromFirstGeo(schemaName, tableName, columnName, cx);
        }

        if (dimension == null) {
            dimension = 2;
        }

        return dimension;
    }

    protected Integer getDimensionFromFirstGeo(String schemaName, String tableName, String columnName, Connection cx)
            throws SQLException {

        Statement statement = null;
        ResultSet result = null;
        try {

            String sqlStatement = "SELECT ST_NDIMS("
                    + escapeName(columnName)
                    + "::geometry) FROM "
                    + escapeName(schemaName)
                    + "."
                    + escapeName(tableName)
                    + " "
                    + "WHERE "
                    + escapeName(columnName)
                    + " IS NOT NULL LIMIT 1";
            statement = cx.createStatement();
            result = statement.executeQuery(sqlStatement);
            if (result.next()) {
                return result.getInt(1);
            }
        } catch (SQLException e) {
            LOGGER.log(
                    Level.WARNING,
                    "Failed to retrieve information about "
                            + schemaName
                            + "."
                            + tableName
                            + "."
                            + columnName
                            + " by examining the first sample geometry",
                    e);
        } finally {
            dataStore.closeSafe(result);
            dataStore.closeSafe(statement);
        }

        return null;
    }

    @Override
    public String getSequenceForColumn(String schemaName, String tableName, String columnName, Connection cx)
            throws SQLException {
        Statement st = cx.createStatement();
        try {


            String sql = "SELECT pg_get_serial_sequence('";
            if (schemaName != null && !"".equals(schemaName)) sql += escapeName(schemaName) + ".";
            sql += escapeName(tableName) + "', '" + columnName + "')";

            dataStore.getLogger().fine(sql);
            ResultSet rs = st.executeQuery(sql);
            try {
                if (rs.next()) {
                    return rs.getString(1);
                }
            } finally {
                dataStore.closeSafe(rs);
            }
        } finally {
            dataStore.closeSafe(st);
        }

        return null;
    }

    @Override
    public Object getNextSequenceValue(String schemaName, String sequenceName, Connection cx) throws SQLException {
        Statement st = cx.createStatement();
        try {
            String sql = "SELECT " + encodeNextSequenceValue(schemaName, sequenceName);

            dataStore.getLogger().fine(sql);
            ResultSet rs = st.executeQuery(sql);
            try {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            } finally {
                dataStore.closeSafe(rs);
            }
        } finally {
            dataStore.closeSafe(st);
        }

        return null;
    }

    @Override
    public String encodeNextSequenceValue(String schemaName, String sequenceName) {
        return "nextval('" + sequenceName + "')";
    }

    @Override
    public boolean lookupGeneratedValuesPostInsert() {
        return true;
    }

    @Override
    public Object getLastAutoGeneratedValue(String schemaName, String tableName, String columnName, Connection cx)
            throws SQLException {

        Statement st = cx.createStatement();
        try {


            String sequenceName = getSequenceForColumn(schemaName, tableName, columnName, cx);
            if (sequenceName == null) {

                return null;
            }

            String sql = "SELECT currval('" + sequenceName + "')";
            dataStore.getLogger().fine(sql);

            ResultSet rs = st.executeQuery(sql);
            try {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            } finally {
                dataStore.closeSafe(rs);
            }
        } finally {
            dataStore.closeSafe(st);
        }

        return null;
    }

    @Override
    public void registerClassToSqlMappings(Map<Class<?>, Integer> mappings) {
        super.registerClassToSqlMappings(mappings);


        mappings.put(Geometry.class, Types.OTHER);
        mappings.put(UUID.class, Types.OTHER);
        mappings.put(HStore.class, Types.OTHER);
        mappings.put(BigDate.class, Types.BIGINT);
    }

    @Override
    public void registerSqlTypeNameToClassMappings(Map<String, Class<?>> mappings) {
        super.registerSqlTypeNameToClassMappings(mappings);

        mappings.put("geometry", Geometry.class);
        mappings.put("geography", Geometry.class);
        mappings.put("text", String.class);
        mappings.put("int8", Long.class);
        mappings.put("int4", Integer.class);
        mappings.put("bool", Boolean.class);
        mappings.put("character", String.class);
        mappings.put("varchar", String.class);
        mappings.put("float8", Double.class);
        mappings.put("int", Integer.class);
        mappings.put("float4", Float.class);
        mappings.put("int2", Short.class);
        mappings.put("time", Time.class);
        mappings.put("timetz", Time.class);
        mappings.put("timestamp", Timestamp.class);
        mappings.put("timestamptz", Timestamp.class);
        mappings.put("uuid", UUID.class);
        mappings.put("hstore", HStore.class);
        mappings.put("json", String.class);
        mappings.put("jsonb", String.class);
    }

    @Override
    public void registerSqlTypeToSqlTypeNameOverrides(Map<Integer, String> overrides) {
        overrides.put(Types.VARCHAR, "VARCHAR");
        overrides.put(Types.BOOLEAN, "BOOL");
        overrides.put(Types.BLOB, "BYTEA");
        overrides.put(Types.CLOB, "TEXT");
    }

    @Override
    public String getGeometryTypeName(Integer type) {
        return "geometry";
    }

    @Override
    public void encodePrimaryKey(String column, StringBuffer sql) {
        encodeColumnName(null, column, sql);
        sql.append(" SERIAL PRIMARY KEY");
    }


    @Override
    public void postCreateTable(String schemaName, SimpleFeatureType featureType, Connection cx) throws SQLException {
        schemaName = schemaName != null ? schemaName : "public";
        String tableName = featureType.getName().getLocalPart();

        Statement st = null;
        try {
            st = cx.createStatement();


            for (AttributeDescriptor att : featureType.getAttributeDescriptors()) {
                if (att instanceof GeometryDescriptor gd) {

                    int srid = getSRIDFromDescriptor(cx, gd);


                    int dimensions = 2;
                    if (gd.getUserData().get(Hints.COORDINATE_DIMENSION) != null) {
                        dimensions = (Integer) gd.getUserData().get(Hints.COORDINATE_DIMENSION);
                    }


                    String geomType = CLASS_TO_TYPE_MAP.get(gd.getType().getBinding());
                    if (geomType == null) {
                        geomType = "GEOMETRY";
                    }

                    String sql = null;
                    if (getVersion(cx).compareTo(V_2_0_0) >= 0) {



                        if (dimensions == 3) {
                            geomType = geomType + "Z";
                        } else if (dimensions == 4) {
                            geomType = geomType + "ZM";
                        } else if (dimensions > 4) {
                            throw new IllegalArgumentException(
                                    "PostGIS only supports geometries with 2, 3 and 4 dimensions, current value: "
                                            + dimensions);
                        }

                        sql = "ALTER TABLE "
                                + escapeName(schemaName)
                                + "."
                                + escapeName(tableName)
                                + " "
                                + "ALTER COLUMN "
                                + escapeName(gd.getLocalName())
                                + " "
                                + "TYPE geometry ("
                                + geomType
                                + ", "
                                + srid
                                + ");";

                        LOGGER.fine(sql);
                        st.execute(sql);
                    } else {


                        sql = "DELETE FROM GEOMETRY_COLUMNS"
                                + " WHERE f_table_catalog=''"
                                + " AND f_table_schema = '"
                                + schemaName
                                + "'"
                                + " AND f_table_name = '"
                                + tableName
                                + "'"
                                + " AND f_geometry_column = '"
                                + gd.getLocalName()
                                + "'";

                        LOGGER.fine(sql);
                        st.execute(sql);

                        sql = "INSERT INTO GEOMETRY_COLUMNS VALUES ('',"
                                + "'"
                                + schemaName
                                + "',"
                                + "'"
                                + tableName
                                + "',"
                                + "'"
                                + gd.getLocalName()
                                + "',"
                                + dimensions
                                + ","
                                + srid
                                + ","
                                + "'"
                                + geomType
                                + "')";
                        LOGGER.fine(sql);
                        st.execute(sql);


                        if (srid > -1) {
                            sql = "ALTER TABLE "
                                    + escapeName(schemaName)
                                    + "."
                                    + escapeName(tableName)
                                    + " ADD CONSTRAINT "
                                    + escapeName("enforce_srid_" + gd.getLocalName())
                                    + " CHECK (ST_SRID("
                                    + escapeName(gd.getLocalName())
                                    + ") = "
                                    + srid
                                    + ")";
                            LOGGER.fine(sql);
                            st.execute(sql);
                        }


                        sql = "ALTER TABLE "
                                + escapeName(schemaName)
                                + "."
                                + escapeName(tableName)
                                + " ADD CONSTRAINT "
                                + escapeName("enforce_dims_" + gd.getLocalName())
                                + " CHECK (st_ndims("
                                + escapeName(gd.getLocalName())
                                + ")"
                                + " = "
                                + dimensions
                                + ")";
                        LOGGER.fine(sql);
                        st.execute(sql);


                        if (!geomType.equals("GEOMETRY")) {
                            sql = "ALTER TABLE "
                                    + escapeName(schemaName)
                                    + "."
                                    + escapeName(tableName)
                                    + " ADD CONSTRAINT "
                                    + escapeName("enforce_geotype_" + gd.getLocalName())
                                    + " CHECK (geometrytype("
                                    + escapeName(gd.getLocalName())
                                    + ") = '"
                                    + geomType
                                    + "'::text "
                                    + "OR "
                                    + escapeName(gd.getLocalName())
                                    + " IS NULL)";
                            LOGGER.fine(sql);
                            st.execute(sql);
                        }
                    }


                    sql = "CREATE INDEX "
                            + escapeName("spatial_"
                                    + tableName
                                    + "_"
                                    + gd.getLocalName().toLowerCase())
                            + " ON "
                            + escapeName(schemaName)
                            + "."
                            + escapeName(tableName)
                            + " USING GIST ("
                            + escapeName(gd.getLocalName())
                            + ")";
                    LOGGER.fine(sql);
                    st.execute(sql);
                }
            }
            if (!cx.getAutoCommit()) {
                cx.commit();
            }
        } finally {
            dataStore.closeSafe(st);
        }
    }

    private static int getSRIDFromDescriptor(Connection cx, GeometryDescriptor gd) {

        CoordinateReferenceSystem crs = gd.getCoordinateReferenceSystem();
        if (gd.getUserData().get(JDBCDataStore.JDBC_NATIVE_SRID) != null)
            return (Integer) gd.getUserData().get(JDBCDataStore.JDBC_NATIVE_SRID);

        if (crs != null) {
            try {
                Integer result = CRS.lookupEpsgCode(crs, true);
                if (result != null) return result;


                String wkt = crs.toWKT();
                String sqlWkt = "SELECT srid FROM spatial_ref_sys WHERE srtext = '" + wkt + "'";
                try (Statement st = cx.createStatement();
                        ResultSet rs = st.executeQuery(sqlWkt)) {
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                }


                String sqlMax = "select max(srid) from spatial_ref_sys";
                String insert = "INSERT INTO spatial_ref_sys (srid, auth_name, auth_srid, srtext) VALUES (?, ?, ?, ?)";
                String identifier = CRS.lookupIdentifier(crs, true);
                int splitIdx = identifier.indexOf(':');
                try (Statement st = cx.createStatement();
                        ResultSet rs = st.executeQuery(sqlMax);
                        PreparedStatement ps = cx.prepareStatement(insert)) {
                    if (rs.next()) {
                        int srid = rs.getInt(1) + 1;
                        ps.setInt(1, srid);
                        if (splitIdx == -1) {
                            ps.setString(2, null);
                            ps.setNull(3, Types.INTEGER);
                        } else {
                            ps.setString(2, identifier.substring(0, splitIdx));
                            ps.setInt(3, Integer.parseInt(identifier.substring(splitIdx + 1)));
                        }
                        ps.setString(4, wkt);
                        ps.execute();
                        return srid;
                    }
                }
            } catch (Exception e) {
                LOGGER.log(Level.FINE, "Error looking up the epsg code for metadata insertion", e);
            }
        }

        return -1;
    }

    @Override
    public void postDropTable(String schemaName, SimpleFeatureType featureType, Connection cx) throws SQLException {
        Statement st = cx.createStatement();
        String tableName = featureType.getTypeName();

        try {

            String sql = "DELETE FROM GEOMETRY_COLUMNS"
                    + " WHERE f_table_catalog=''"
                    + " AND f_table_schema = '"
                    + schemaName
                    + "'"
                    + " AND f_table_name = '"
                    + tableName
                    + "'";
            LOGGER.fine(sql);
            st.execute(sql);
        } finally {
            dataStore.closeSafe(st);
        }
    }

    @Override
    public void encodeGeometryValue(Geometry value, int dimension, int srid, StringBuffer sql) throws IOException {
        if (value == null) {
            sql.append("NULL");
        } else {
            if (value instanceof LinearRing ring && !(value instanceof CurvedRing)) {

                value = value.getFactory().createLineString(ring.getCoordinateSequence());
            }

            WKTWriter writer = new WKTWriter2(dimension);
            String wkt = writer.write(value);
            sql.append("ST_GeomFromText('" + wkt + "', " + srid + ")");
        }
    }

    @Override
    public FilterToSQL createFilterToSQL() {
        PostgisFilterToSQL sql = new PostgisFilterToSQL(this, pgsqlVersion);
        sql.setLooseBBOXEnabled(looseBBOXEnabled);
        sql.setEncodeBBOXFilterAsEnvelope(encodeBBOXFilterAsEnvelope);
        sql.setFunctionEncodingEnabled(functionEncodingEnabled);
        sql.setEscapeBackslash(escapeBackslash);
        return sql;
    }

    @Override
    public boolean isLimitOffsetSupported() {
        return true;
    }

    @Override
    public void applyLimitOffset(StringBuffer sql, int limit, int offset) {
        if (limit >= 0 && limit < Integer.MAX_VALUE) {
            sql.append(" LIMIT " + limit);
            if (offset > 0) {
                sql.append(" OFFSET " + offset);
            }
        } else if (offset > 0) {
            sql.append(" OFFSET " + offset);
        }
    }

    @Override
    public void encodeValue(Object value, Class type, StringBuffer sql) {
        if (byte[].class.equals(type)) {
            byte[] input = (byte[]) value;

            if (pgsqlVersion.compareTo(PGSQL_V_9_1) >= 0) {
                encodeByteArrayAsHex(input, sql);
            } else {
                encodeByteArrayAsEscape(input, sql);
            }
            return;
        }

        if (BigDate.class.isAssignableFrom(type)) {
            if (value instanceof Date date) {
                super.encodeValue(date.getTime(), Long.class, sql);
                return;
            }
        }

        if (type.isArray() && value != null) {
            this.encodeArray(value, type, sql);
            return;
        }

        super.encodeValue(value, type, sql);
    }

    private void encodeArray(Object value, Class type, StringBuffer sql) {
        int length = Array.getLength(value);
        sql.append("ARRAY[");
        for (int i = 0; i < length; i++) {
            Object element = Array.get(value, i);
            encodeValue(element, type.getComponentType(), sql);
            if (i < length - 1) {
                sql.append(", ");
            }
        }
        sql.append("]");
    }

    void encodeByteArrayAsHex(byte[] input, StringBuffer sql) {
        StringBuffer sb = new StringBuffer("\\x");
        for (byte b : input) {
            sb.append("%02x".formatted(b));
        }
        super.encodeValue(sb.toString(), String.class, sql);
    }

    void encodeByteArrayAsEscape(byte[] input, StringBuffer sql) {

        StringBuffer sb = new StringBuffer();
        for (byte b : input) {
            if (b == 0) {
                sb.append("\\\\000");
            } else if (b == 39) {
                sb.append("\\'");
            } else if (b == 92) {
                sb.append("\\\\134'");
            } else if (b < 31 || b >= 127) {
                sb.append("\\\\");
                String octal = Integer.toOctalString(b);
                if (octal.length() == 1) {
                    sb.append("00");
                } else if (octal.length() == 2) {
                    sb.append("0");
                }
                sb.append(octal);
            } else {
                sb.append((char) b);
            }
        }
        super.encodeValue(sb.toString(), String.class, sql);
    }

    @Override
    public int getDefaultVarcharSize() {
        return -1;
    }


    public Version getVersion(Connection conn) throws SQLException {
        if (version == null) {
            Statement st = null;
            ResultSet rs = null;
            try {
                st = conn.createStatement();
                rs = st.executeQuery("select PostGIS_Lib_Version()");
                if (rs.next()) {
                    version = new Version(rs.getString(1));
                }
            } finally {
                dataStore.closeSafe(rs);
                dataStore.closeSafe(st);
            }
        }

        return version;
    }


    public Version getPostgreSQLVersion(Connection conn) throws SQLException {
        if (pgsqlVersion == null) {
            DatabaseMetaData md = conn.getMetaData();
            pgsqlVersion = new Version("%d.%d".formatted(md.getDatabaseMajorVersion(), md.getDatabaseMinorVersion()));
        }
        return pgsqlVersion;
    }





    private void checkStandardConformingStrings(Connection conn) throws SQLException {
        Boolean escape = null;

        try {
            PgConnection bc = unwrapConnection(conn, PgConnection.class);
            escape = !bc.getStandardConformingStrings();
        } catch (SQLException e) {
            LOGGER.log(Level.FINER, "Unable to get native connection; falling back to query", e);
        }

        if (escape == null) {
            Statement st = null;
            ResultSet rs = null;
            try {
                st = conn.createStatement();
                rs = st.executeQuery("SHOW standard_conforming_strings");
                escape = !rs.next() || !"on".equals(rs.getString(1));
            } catch (SQLException e) {
                LOGGER.warning("Unable to check standard_conforming_strings setting: " + e.getMessage());
            } finally {
                dataStore.closeSafe(rs);
                dataStore.closeSafe(st);
            }
        }

        escapeBackslash = !Boolean.FALSE.equals(escape);
    }


    boolean supportsGeography(Connection cx) throws SQLException {
        return getVersion(cx).compareTo(V_1_5_0) >= 0;
    }

    @Override
    protected void addSupportedHints(Set<Hints.Key> hints) {
        if (isSimplifyEnabled()) {
            hints.add(Hints.GEOMETRY_SIMPLIFICATION);
        }
    }






    String getForce2DFunction() {
        return version == null || version.compareTo(V_2_1_0) >= 0 ? "ST_Force2D" : "ST_Force_2D";
    }






    protected String getEstimatedExtentFunction() {
        return version == null || version.compareTo(V_2_1_0) >= 0 ? "ST_EstimatedExtent" : "ST_Estimated_Extent";
    }

    @Override
    public Filter[] splitFilter(Filter filter, SimpleFeatureType schema) {

        PostPreProcessFilterSplittingVisitor splitter =
                new JsonPointerFilterSplittingVisitor(dataStore.getFilterCapabilities(), schema, null);
        filter.accept(splitter, null);

        Filter[] split = new Filter[2];
        split[0] = splitter.getFilterPre();
        split[1] = splitter.getFilterPost();

        return split;
    }

    @Override
    public String[] getDesiredTablesType() {
        return new String[] {"TABLE", "VIEW", "MATERIALIZED VIEW", "SYNONYM", "PARTITIONED TABLE"};
    }

    @Override
    public boolean canGroupOnGeometry() {
        return true;
    }
}
