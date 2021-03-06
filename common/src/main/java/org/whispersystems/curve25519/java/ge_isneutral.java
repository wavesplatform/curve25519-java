package org.whispersystems.curve25519.java;

public class ge_isneutral {
    /**
     * Checks that the point is neutral
     *
     * @param p point
     * @return true if p is the neutral point, false otherwise
     */
    public static boolean ge_isneutral(ge_p3 p) {
        int[] zero = new int[10];
        fe_0.fe_0(zero);

        /* Check if p == neutral element == (0, 1) */
        return (fe_isequal.fe_isequal(p.X, zero) & fe_isequal.fe_isequal(p.Y, p.Z)) == 1;
    }
}
