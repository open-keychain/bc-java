package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;


/**
 * Represents intended recipient OpenPGP signature sub packet.
 */
public class IntendedRecipientFingerprint extends SignatureSubpacket
{
    public IntendedRecipientFingerprint(boolean isCritical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.INTENDED_RECIPIENT, isCritical, isLongLength, data);
    }

    public IntendedRecipientFingerprint(boolean isCritical, byte[] fingerprint)
    {
        super(SignatureSubpacketTags.INTENDED_RECIPIENT, isCritical, false, createData(fingerprint));
    }

    private static byte[] createData(byte[] fingerprint)
    {
        byte[] data = new byte[1 + fingerprint.length];
        data[0] = 0x04;
        System.arraycopy(fingerprint, 0, data, 1, fingerprint.length);
        return data;
    }

    public byte[] getFingerprint()
    {
        byte[] data = this.getData();
        byte[] fingerprint = new byte[data.length - 1];
        System.arraycopy(data, 1, fingerprint, 0, fingerprint.length);
        return fingerprint;
    }
}
