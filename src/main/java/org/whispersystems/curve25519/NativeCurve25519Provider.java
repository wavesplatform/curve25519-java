package org.whispersystems.curve25519;

/**
 * Native provider backed by curve25519-dalek through JNI. Produces byte-for-byte the same
 * keys, agreements and (given the same randomness) signatures as {@link JavaCurve25519Provider}.
 */
public class NativeCurve25519Provider implements Curve25519Provider {
    private SecureRandomProvider secureRandomProvider = new JCESecureRandomProvider();

    public NativeCurve25519Provider() {
        NativeCurve25519.ensureAvailable();
    }

    /** Hardware acceleration used by the native library, e.g. {@code "curve=avx2 sha512=avx2"}. */
    public static String backend() {
        NativeCurve25519.ensureAvailable();
        return NativeCurve25519.backend();
    }

    @Override
    public boolean isNative() {
        return true;
    }

    @Override
    public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic) {
        byte[] sharedKey = new byte[32];
        checkArguments(NativeCurve25519.calculateAgreement(sharedKey, ourPrivate, theirPublic));
        return sharedKey;
    }

    @Override
    public byte[] generatePublicKey(byte[] privateKey) {
        byte[] publicKey = new byte[32];
        checkArguments(NativeCurve25519.generatePublicKey(publicKey, privateKey));
        return publicKey;
    }

    @Override
    public byte[] generatePrivateKey() {
        return generatePrivateKey(getRandom(PRIVATE_KEY_LEN));
    }

    @Override
    public byte[] generatePrivateKey(byte[] random) {
        random[0] &= (byte) 248;
        random[31] &= 127;
        random[31] |= 64;
        return random;
    }

    @Override
    public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message) {
        byte[] signature = new byte[64];
        int result = NativeCurve25519.calculateSignature(signature, random, privateKey, message);
        checkArguments(result);
        if (result != NativeCurve25519.OK) throw new AssertionError("Signature failed!");
        return signature;
    }

    @Override
    public boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
        return NativeCurve25519.verifySignature(publicKey, message, signature) == NativeCurve25519.OK;
    }

    @Override
    public byte[] calculateVrfSignature(byte[] random, byte[] privateKey, byte[] message) {
        byte[] signature = new byte[96];
        int result = NativeCurve25519.calculateVrfSignature(signature, random, privateKey, message);
        checkArguments(result);
        if (result != NativeCurve25519.OK) throw new AssertionError("Signature failed!");
        return signature;
    }

    @Override
    public byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
            throws VrfSignatureVerificationFailedException {
        byte[] vrf = new byte[32];
        if (NativeCurve25519.verifyVrfSignature(vrf, publicKey, message, signature) != NativeCurve25519.OK) {
            throw new VrfSignatureVerificationFailedException("Invalid signature");
        }
        return vrf;
    }

    @Override
    public byte[] getRandom(int length) {
        byte[] result = new byte[length];
        secureRandomProvider.nextBytes(result);
        return result;
    }

    @Override
    public void setRandomProvider(SecureRandomProvider provider) {
        this.secureRandomProvider = provider;
    }

    private static void checkArguments(int result) {
        if (result == NativeCurve25519.ERR_ARGUMENT) {
            throw new IllegalArgumentException("Null or too short key, random, message or output array");
        }
    }
}
