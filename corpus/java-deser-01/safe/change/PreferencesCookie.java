package shop;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class PreferencesCookie {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Restore the preferences a browser sent back in a cookie. */
    public static Preferences read(String cookie) throws IOException {
        byte[] raw = TokenStore.decode(cookie);
        return MAPPER.readValue(raw, Preferences.class);
    }
}
