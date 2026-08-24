















package org.geotools.data.postgis;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;

public class HStore extends HashMap<String, String> {

    @Serial
    private static final long serialVersionUID = -2696388478311744741L;

    public static final String TYPENAME = "hstore";

    private static final String EMPTY = "{}";

    private static final String NULL = "null";

    public HStore(Map<String, String> map) {
        if (map != null) {
            putAll(map);
        }
    }

    @Override
    public String toString() {

        if (isEmpty()) {
            return EMPTY;
        }

        StringBuilder sb = new StringBuilder("{");
        String prefix = "";
        for (Map.Entry<String, String> entry : entrySet()) {
            sb.append(prefix);
            sb.append(doubleQuoteString(entry.getKey())).append(":").append(doubleQuoteString(entry.getValue()));
            prefix = ",";
        }
        sb.append("}");
        return sb.toString();
    }

    private static final String doubleQuoteString(String string) {
        return string != null ? "\"" + string + "\"" : NULL;
    }
}
