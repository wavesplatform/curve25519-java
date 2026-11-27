package org.whispersystems.curve25519;

public class NativeCurve25519Test extends Curve25519Test {
    @Override
    public void testCheckProvider() throws NoSuchProviderException {
        assertTrue(Curve25519.getInstance(getProviderName()).isNative());
        assertTrue(Curve25519.getInstance(Curve25519.BEST).isNative());
    }

    @Override
    public String getProviderName() {
        return Curve25519.NATIVE;
    }
}
