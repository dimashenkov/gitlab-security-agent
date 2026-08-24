


















package org.xwiki.livedata.internal.livetable;

import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;







public class URLQueryStringParser
{
    private static final String UTF8 = "UTF-8";








    public Map<String, List<String>> parse(String url) throws Exception
    {
        URL baseURL = new URL("http://www.xwiki.org");
        String queryString = new URL(baseURL, url).getQuery();
        Map<String, List<String>> parameters = new HashMap<>();
        for (String entry : queryString.split("&")) {
            String[] parts = entry.split("=", 2);
            String key = URLDecoder.decode(parts[0], UTF8);
            if (key.isEmpty()) {
                continue;
            }
            String value = parts.length == 2 ? URLDecoder.decode(parts[1], UTF8) : "";
            List<String> values = parameters.get(key);
            if (values == null) {
                values = new ArrayList<>();
                parameters.put(key, values);
            }
            values.add(value);
        }
        return parameters;
    }
}
