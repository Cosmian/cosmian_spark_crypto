package com.cosmian.spark;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.crypto.KeyAccessDeniedException;

public interface KmsClient {

    /**
     * Pass configuration with KMS-specific parameters.
     * 
     * @param configuration  Hadoop configuration
     * @param kmsInstanceID  ID of the KMS instance handled by this KmsClient. Use
     *                       the default value, for KMS systems
     *                       that don't work with multiple instances.
     * @param kmsInstanceURL URL of the KMS instance handled by this KmsClient. Use
     *                       the default value, for KMS systems
     *                       that don't work with URLs.
     * @param accessToken    KMS access (authorization) token. Use the default
     *                       value, for KMS systems that don't work with tokens.
     * @throws KeyAccessDeniedException unauthorized to initialize the KMS client
     */
    public void initialize(Configuration configuration, String kmsInstanceID, String kmsInstanceURL, String accessToken)
            throws KeyAccessDeniedException;

    /**
     * Retrieve the serialized version of the ABE
     * {@link com.cosmian.rest.kmip.objects.PublicKey} from the MS Server
     * 
     * @return the bytes
     * @throws KeyAccessDeniedException if the public key cannot be retrieved
     */
    public byte[] retrievePublicKey() throws KeyAccessDeniedException;

    /**
     * Retrieve the serialized version of the ABE
     * {@link com.cosmian.rest.kmip.objects.PrivateKey} from the MS Server
     * 
     * @param privateKeyId the id of the PrivateKey inside the KMS
     * @return the bytes of the key
     * @throws KeyAccessDeniedException if the key cannot b retrieved
     */
    public byte[] retrievePrivateKey(String privateKeyId) throws KeyAccessDeniedException;

}
