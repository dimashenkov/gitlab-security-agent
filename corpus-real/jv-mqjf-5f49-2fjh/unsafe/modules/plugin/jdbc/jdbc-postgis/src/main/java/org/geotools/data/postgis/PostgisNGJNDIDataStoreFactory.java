















package org.geotools.data.postgis;

import static org.geotools.data.postgis.PostgisNGDataStoreFactory.ENCODE_FUNCTIONS;
import static org.geotools.data.postgis.PostgisNGDataStoreFactory.ESTIMATED_EXTENTS;
import static org.geotools.data.postgis.PostgisNGDataStoreFactory.LOOSEBBOX;
import static org.geotools.data.postgis.PostgisNGDataStoreFactory.PREPARED_STATEMENTS;
import static org.geotools.data.postgis.PostgisNGDataStoreFactory.SIMPLIFICATION_METHOD;
import static org.geotools.data.postgis.PostgisNGDataStoreFactory.SIMPLIFY;

import java.util.Map;
import org.geotools.jdbc.JDBCJNDIDataStoreFactory;







@SuppressWarnings("unchecked")
public class PostgisNGJNDIDataStoreFactory extends JDBCJNDIDataStoreFactory {

    public PostgisNGJNDIDataStoreFactory() {
        super(new PostgisNGDataStoreFactory());
    }

    @Override
    protected void setupParameters(Map parameters) {
        super.setupParameters(parameters);

        parameters.put(LOOSEBBOX.key, LOOSEBBOX);
        parameters.put(ESTIMATED_EXTENTS.key, ESTIMATED_EXTENTS);
        parameters.put(PREPARED_STATEMENTS.key, PREPARED_STATEMENTS);
        parameters.put(ENCODE_FUNCTIONS.key, ENCODE_FUNCTIONS);
        parameters.put(SIMPLIFY.key, SIMPLIFY);
        parameters.put(SIMPLIFICATION_METHOD.key, SIMPLIFICATION_METHOD);
    }
}
