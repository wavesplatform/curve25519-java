package org.whispersystems.curve25519;

import junit.framework.TestCase;

import java.util.Arrays;
import java.util.Random;

/**
 * Differential test: the native (curve25519-dalek) provider must agree with the pure-Java
 * ref10 port on every operation, including malformed and edge-case inputs.
 *
 * <p>Signing is the one intentional difference inherited from the legacy native library:
 * it produces XEdDSA signatures (private key negated so the Edwards sign bit is 0), while the
 * Java provider embeds the sign bit in the signature. Both verify under the same algorithm,
 * and they are byte-identical whenever the sign bit is already 0.
 */
public class NativeVsJavaCurve25519Test extends TestCase {
    private static final int ITERATIONS = 500;

    private final Curve25519Provider nat = new NativeCurve25519Provider();
    private final Curve25519Provider java = new JavaCurve25519Provider();
    private final Random random = new Random(0x25519);

    private byte[] bytes(int len) {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }

    private byte[] clampedKey() {
        return java.generatePrivateKey(bytes(32));
    }

    /** Arbitrary private key (bit 255 clear, as ref10's fixed-base multiplication requires). */
    private byte[] rawKey() {
        byte[] k = bytes(32);
        k[31] &= 0x7f;
        return k;
    }

    private static byte[] edgeValue(int i) {
        byte[] b = new byte[32];
        switch (i) {
            case 0: break;                                              // 0
            case 1: b[0] = 1; break;                                    // 1
            case 2: Arrays.fill(b, (byte) 0xff); b[0] = (byte) 0xec; b[31] = 0x7f; break; // p - 1 = -1
            case 3: Arrays.fill(b, (byte) 0xff); b[0] = (byte) 0xed; b[31] = 0x7f; break; // p (non-canonical 0)
            case 4: Arrays.fill(b, (byte) 0xff); b[31] = 0x7f; break;  // 2^255 - 1 (non-canonical)
            case 5: Arrays.fill(b, (byte) 0xff); break;                 // high bit set
            default: b[0] = 9; break;                                   // base point
        }
        return b;
    }

    public void testPublicKeys() {
        for (int i = 0; i < ITERATIONS; i++) {
            byte[] k = i % 2 == 0 ? clampedKey() : rawKey();
            assertTrue(Arrays.equals(java.generatePublicKey(k), nat.generatePublicKey(k)));
        }
        for (int i = 0; i < 7; i++) {
            byte[] k = edgeValue(i);
            k[31] &= 0x7f;
            assertTrue("edge " + i, Arrays.equals(java.generatePublicKey(k), nat.generatePublicKey(k)));
        }
    }

    public void testPrivateKeyClamping() {
        for (int i = 0; i < 50; i++) {
            byte[] r = bytes(32);
            assertTrue(Arrays.equals(java.generatePrivateKey(r.clone()), nat.generatePrivateKey(r.clone())));
        }
    }

    public void testAgreement() {
        for (int i = 0; i < ITERATIONS; i++) {
            // ECDH is unclamped in both. Keys with bit 255 set are excluded: the Java ref10
            // ladder ignores that bit while the native (like the legacy donna code) uses it.
            byte[] k = i % 3 == 0 ? rawKey() : clampedKey();
            byte[] pub = i % 2 == 0 ? java.generatePublicKey(clampedKey()) : bytes(32);
            assertTrue(Arrays.equals(java.calculateAgreement(k, pub), nat.calculateAgreement(k, pub)));
        }
        for (int i = 0; i < 7; i++) {
            byte[] k = clampedKey();
            byte[] pub = edgeValue(i);
            assertTrue("edge " + i, Arrays.equals(java.calculateAgreement(k, pub), nat.calculateAgreement(k, pub)));
        }
    }

    public void testSignatures() {
        int identical = 0;
        for (int i = 0; i < ITERATIONS; i++) {
            byte[] k = i % 2 == 0 ? clampedKey() : rawKey();
            byte[] pub = java.generatePublicKey(k);
            byte[] msg = bytes(i % 200);
            byte[] rnd = bytes(64);

            byte[] javaSig = java.calculateSignature(rnd, k, msg);
            byte[] natSig = nat.calculateSignature(rnd, k, msg);
            assertEquals(0, natSig[63] & 0x80);
            if ((javaSig[63] & 0x80) == 0) {
                assertTrue(Arrays.equals(javaSig, natSig));
                identical++;
            }

            for (byte[] sig : new byte[][]{javaSig, natSig}) {
                assertTrue(java.verifySignature(pub, msg, sig));
                assertTrue(nat.verifySignature(pub, msg, sig));
                assertSameVerification(pub, msg, tamper(sig, random.nextInt(64)));
                if (msg.length > 0) assertSameVerification(pub, tamper(msg, random.nextInt(msg.length)), sig);
                assertSameVerification(tamper(pub, random.nextInt(32)), msg, sig);
            }
            assertSameVerification(pub, msg, bytes(64));
        }
        assertTrue("expected roughly half identical signatures, got " + identical, identical > ITERATIONS / 4);

        for (int i = 0; i < 7; i++) {
            byte[] sig = bytes(64);
            sig[63] &= 0x0f;
            assertSameVerification(edgeValue(i), bytes(10), sig);
        }
    }

    public void testVrf() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            byte[] k = i % 2 == 0 ? clampedKey() : rawKey();
            byte[] pub = java.generatePublicKey(k);
            byte[] msg = bytes(i % 200);
            byte[] rnd = bytes(32);

            byte[] javaSig = java.calculateVrfSignature(rnd, k, msg);
            byte[] natSig = nat.calculateVrfSignature(rnd, k, msg);
            assertTrue(Arrays.equals(javaSig, natSig));
            assertTrue(Arrays.equals(java.verifyVrfSignature(pub, msg, natSig), nat.verifyVrfSignature(pub, msg, natSig)));

            assertSameVrf(pub, msg, tamper(natSig, random.nextInt(96)));
            if (msg.length > 0) assertSameVrf(pub, tamper(msg, random.nextInt(msg.length)), natSig);
            assertSameVrf(tamper(pub, random.nextInt(32)), msg, natSig);
            byte[] highBit = pub.clone();
            highBit[31] |= (byte) 0x80;
            assertSameVrf(highBit, msg, natSig);
        }
        for (int i = 0; i < 7; i++) {
            assertSameVrf(edgeValue(i), bytes(10), bytes(96));
        }
    }

    public void testVrfMessageLimit() throws Exception {
        byte[] k = clampedKey();
        byte[] pub = java.generatePublicKey(k);
        byte[] max = bytes(1048576);
        byte[] sig = nat.calculateVrfSignature(bytes(32), k, max);
        assertTrue(Arrays.equals(java.verifyVrfSignature(pub, max, sig), nat.verifyVrfSignature(pub, max, sig)));

        byte[] tooLong = new byte[1048577];
        try {
            nat.calculateVrfSignature(bytes(32), k, tooLong);
            fail("message over 1 MiB must be rejected");
        } catch (AssertionError expected) {
        }
        assertSameVrf(pub, tooLong, sig);
    }

    public void testLargeMessageSignature() {
        byte[] k = clampedKey();
        byte[] pub = java.generatePublicKey(k);
        byte[] msg = bytes(4 * 1024 * 1024);
        byte[] sig = nat.calculateSignature(bytes(64), k, msg);
        assertTrue(java.verifySignature(pub, msg, sig));
        assertTrue(nat.verifySignature(pub, msg, sig));
    }

    public void testShortArraysRejected() {
        try {
            nat.generatePublicKey(new byte[31]);
            fail();
        } catch (IllegalArgumentException expected) {
        }
        try {
            nat.calculateSignature(new byte[63], clampedKey(), new byte[1]);
            fail();
        } catch (IllegalArgumentException expected) {
        }
        assertFalse(nat.verifySignature(new byte[32], new byte[1], new byte[63]));
        assertFalse(nat.verifySignature(new byte[32], null, new byte[64]));
    }

    private void assertSameVerification(byte[] pub, byte[] msg, byte[] sig) {
        assertEquals(java.verifySignature(pub, msg, sig), nat.verifySignature(pub, msg, sig));
    }

    private void assertSameVrf(byte[] pub, byte[] msg, byte[] sig) {
        byte[] j = vrfOrNull(java, pub, msg, sig);
        byte[] n = vrfOrNull(nat, pub, msg, sig);
        assertTrue(Arrays.equals(j, n));
    }

    private static byte[] vrfOrNull(Curve25519Provider p, byte[] pub, byte[] msg, byte[] sig) {
        try {
            return p.verifyVrfSignature(pub, msg, sig);
        } catch (VrfSignatureVerificationFailedException e) {
            return null;
        }
    }

    private byte[] tamper(byte[] in, int index) {
        byte[] out = in.clone();
        out[index] ^= (byte) (1 << random.nextInt(8));
        return out;
    }
}
