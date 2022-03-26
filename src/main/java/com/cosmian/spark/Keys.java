package com.cosmian.spark;

import java.util.Arrays;
import java.util.Objects;

import org.apache.commons.codec.binary.Hex;

/**
 * Holds the generated symmetric key
 * and its ABE encrypted version
 */
public class Keys {

    private final byte[] clearTextKey;
    private final byte[] encryptedKey;

    public Keys(byte[] clearTextKey, byte[] encryptedKey) {
        this.clearTextKey = clearTextKey;
        this.encryptedKey = encryptedKey;
    }

    /**
     * The clear text symmetric key (i.e. the footer key)
     * 
     * @return the bytes of the generated symmetric key
     */
    public byte[] getClearTextKey() {
        return this.clearTextKey;
    }

    /**
     * The encrypted symmetric key (the footer key metadata)
     * 
     * @return the ABE encrypted clear text symmetric key
     */
    public byte[] getEncryptedKey() {
        return this.encryptedKey;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Keys)) {
            return false;
        }
        Keys keys = (Keys) o;
        return Arrays.equals(clearTextKey, keys.clearTextKey) && Arrays.equals(encryptedKey, keys.encryptedKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clearTextKey, encryptedKey);
    }

    @Override
    public String toString() {
        return "{" +
                " clearTextKey = '" + Hex.encodeHexString(getClearTextKey()) + "'" +
                ", encryptedKey = '" + Hex.encodeHexString(getEncryptedKey()) + "'" +
                "}";
    }

}
