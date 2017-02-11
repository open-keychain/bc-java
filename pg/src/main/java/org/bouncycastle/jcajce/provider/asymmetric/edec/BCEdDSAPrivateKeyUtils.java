package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

public class BCEdDSAPrivateKeyUtils {
    public static BCEdDSAPrivateKey newInstance(byte[] raw) {
        return new BCEdDSAPrivateKey(new Ed25519PrivateKeyParameters(raw, 0));
    }

    public static byte[] getSeed(BCEdDSAPrivateKey privateKey) {
        return ((Ed25519PrivateKeyParameters) privateKey.engineGetKeyParameters()).getEncoded();
    }
}
