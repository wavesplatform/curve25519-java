package org.whispersystems.curve25519;

import java.util.HexFormat;

public class HexBin {
    public static byte[] decode(String hexString) {
        return HexFormat.of().parseHex(hexString);
    }
}
