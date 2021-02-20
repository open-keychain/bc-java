package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * base class for an EdDSA Public Key.
 */
public class EdDSAPublicBCPGKey
    extends ECPublicBCPGKey
{
    /**
     * @param in the stream to read the packet from.
     */
    protected EdDSAPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);
    }

    public EdDSAPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point)
    {
        super(oid, point);
    }

    public EdDSAPublicBCPGKey(
           ASN1ObjectIdentifier oid,
           BigInteger encodedPoint)
    {
        super(oid, encodedPoint);
    }

    public byte[] getEdDSAEncodedPoint()
    {
        BigInteger encodedPoint = getEncodedPoint();
        byte[] pointData = BigIntegers.asUnsignedByteArray(encodedPoint);
        if (pointData[0] != 0x40)
        {
            throw new IllegalStateException("Invalid point format in EdDSA key!");
        }
        return Arrays.copyOfRange(pointData, 1, pointData.length);
    }
}
