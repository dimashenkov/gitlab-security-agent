















package org.geotools.data.postgis;

import org.geotools.util.Converter;
import org.geotools.util.ConverterFactory;
import org.geotools.util.factory.Hints;






public class BigDateConverterFactory implements ConverterFactory {

    @Override
    public Converter createConverter(Class<?> source, Class<?> target, Hints hints) {
        if (BigDate.class.equals(target) && Long.class.equals(source)) {
            return new Converter() {

                @Override
                public <T> T convert(Object source, Class<T> target) throws Exception {
                    return target.cast(new BigDate((Long) source));
                }
            };
        }
        return null;
    }
}
