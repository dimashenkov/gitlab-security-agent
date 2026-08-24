















package org.geotools.data.postgis;

import static java.lang.reflect.Array.get;
import static java.lang.reflect.Array.getLength;
import static java.lang.reflect.Array.newInstance;
import static java.lang.reflect.Array.set;

import java.sql.Array;
import org.geotools.util.Converter;
import org.geotools.util.ConverterFactory;
import org.geotools.util.Converters;
import org.geotools.util.factory.Hints;


public class SQLArrayConverterFactory implements ConverterFactory {

    public static final SQLArrayToJavaConverter ARRAY_TO_JAVA_CONVERTER = new SQLArrayToJavaConverter();

    @Override
    public Converter createConverter(Class<?> source, Class<?> target, Hints hints) {
        if (target.isArray() && Array.class.isAssignableFrom(source)) {
            return ARRAY_TO_JAVA_CONVERTER;
        }
        return null;
    }

    static class SQLArrayToJavaConverter implements Converter {

        @Override
        public <T> T convert(Object source, Class<T> target) throws Exception {
            Array sqlArray = (Array) source;
            Object array = sqlArray.getArray();
            int length = getLength(array);
            Class<?> componentType = target.getComponentType();
            Object result = newInstance(componentType, length);
            for (int i = 0; i < length; i++) {
                Object original = get(array, i);
                if (original == null) {
                    set(result, i, null);
                } else {
                    Object converted = Converters.convert(original, componentType);
                    if (converted == null) {
                        throw new RuntimeException("Failed to convert " + original + " to " + componentType);
                    }
                    set(result, i, converted);
                }
            }

            return target.cast(result);
        }
    }
}
