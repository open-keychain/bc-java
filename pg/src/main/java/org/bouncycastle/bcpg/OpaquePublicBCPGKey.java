package org.bouncycastle.bcpg;


import java.io.IOException;
import java.math.BigInteger;


/**
 * A public key with opaque data. Can be read and written as-is, but not perform actual crypto operations.
 */
public class OpaquePublicBCPGKey
    extends BCPGObject implements BCPGKey
{

    private final byte[] data;

    /**
     * Construct an opaque public key from the passed in stream.
     *
     * @param in
     * @throws IOException
     */
    public OpaquePublicBCPGKey(
        BCPGInputStream    in)
        throws IOException
    {
        this.data = in.readAll();
    }

    /**
     * @param data the public exponent
     */
    public OpaquePublicBCPGKey(
        byte[] data)
    {
        this.data = data;
    }

    /**
     *  return "PGP"
     *
     * @see BCPGKey#getFormat()
     */
    public String getFormat()
    {
        return "PGP";
    }

    /**
     * return the standard PGP encoding of the key.
     *
     * @see BCPGKey#getEncoded()
     */
    public byte[] getEncoded() 
    {
        try
        {
            return super.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.write(data);
    }
}
