package shop;

import java.util.Base64;

public class TokenStore {

    public static byte[] decode(String cookie) {
        return Base64.getDecoder().decode(cookie);
    }
}
