package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.security.spec.InvalidKeySpecException;

public class BCEdDSAPublicKeyUtils {
    public static BCEdDSAPublicKey newInstance(byte[] raw) throws InvalidKeySpecException {
        return new BCEdDSAPublicKey(new byte[0], raw);
    }

    public static byte[] getEncodedPoint(BCEdDSAPublicKey publicKey) {
        return ((Ed25519PublicKeyParameters) publicKey.engineGetKeyParameters()).getEncoded();
    }
}
