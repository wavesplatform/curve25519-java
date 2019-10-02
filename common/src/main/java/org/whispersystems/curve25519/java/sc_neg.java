package org.whispersystems.curve25519.java;

public class sc_neg {
    static byte[] lminus1 = {(byte)0xec, (byte)0xd3, (byte)0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            (byte)0xd6, (byte)0x9c, (byte)0xf7, (byte)0xa2, (byte)0xde, (byte)0xf9, (byte)0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

    /* b = -a (mod l) */
    public static void sc_neg(byte[] b, byte[] a)
    {
        byte[] zero = new byte[32];
        sc_muladd.sc_muladd(b, lminus1, a, zero); /* b = (-1)a + 0   (mod l) */
    }
}