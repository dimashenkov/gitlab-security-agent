















package org.geotools.data.postgis;

import java.util.Map;
import org.geotools.util.Converter;
import org.geotools.util.ConverterFactory;
import org.geotools.util.factory.Hints;






public class HStoreConverterFactory implements ConverterFactory {

    @Override
    public Converter createConverter(Class<?> source, Class<?> target, Hints hints) {
        if (HStore.class.equals(target) && Map.class.isAssignableFrom(source)) {
            return new Converter() {

                @Override
                public <T> T convert(Object source, Class<T> target) throws Exception {
                    @SuppressWarnings("unchecked")
                    Map<String, String> cast = (Map<String, String>) source;
                    return target.cast(new HStore(cast));
                }
            };
        }
        return null;
    }
}
