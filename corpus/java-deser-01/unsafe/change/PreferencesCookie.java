package shop;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class PreferencesCookie {

    /** Restore the preferences a browser sent back in a cookie. */
    public static Preferences read(String cookie) throws IOException, ClassNotFoundException {
        byte[] raw = TokenStore.decode(cookie);
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(raw))) {
            return (Preferences) in.readObject();
        }
    }
}
