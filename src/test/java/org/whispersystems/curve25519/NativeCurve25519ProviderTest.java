package org.whispersystems.curve25519;

public class NativeCurve25519ProviderTest extends Curve25519ProviderTest {
    @Override
    protected Curve25519Provider createProvider() {
        return new NativeCurve25519Provider();
    }

    public void testBackendReported() {
        String backend = NativeCurve25519Provider.backend();
        System.out.println("curve25519 native backend: " + backend);
        assertTrue(backend, backend.startsWith("curve="));
    }
}
