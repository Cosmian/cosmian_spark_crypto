package com.cosmian.spark;

import com.cosmian.CosmianException;
import com.cosmian.rest.abe.acccess_policy.Attr;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.crypto.DecryptionKeyRetriever;
import org.apache.parquet.crypto.DecryptionPropertiesFactory;
import org.apache.parquet.crypto.EncryptionPropertiesFactory;
import org.apache.parquet.crypto.FileDecryptionProperties;
import org.apache.parquet.crypto.FileEncryptionProperties;
import org.apache.parquet.crypto.KeyAccessDeniedException;
import org.apache.parquet.crypto.ParquetCipher;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.parquet.hadoop.api.WriteSupport.WriteContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CosmianAbeFactory implements EncryptionPropertiesFactory, DecryptionPropertiesFactory {

    /**
     * The class of the implementation the KMS Client to use
     */
    public static final String COSMIAN_KMS_CLIENT_CLASS = "com.cosmian.kms.client.class";

    /**
     * URL of the KMS server passed to the KMS Client
     */
    public static final String COSMIAN_KMS_CLIENT_URL = "com.cosmian.kms.client.url";

    /**
     * ID of the KMS server instance passed to the KMS Client
     */
    public static final String COSMIAN_KMS_CLIENT_INSTANCE_ID = "com.cosmian.kms.client.instance.id";

    /**
     * Access token the KMS server passed to the KMS Client
     */
    public static final String COSMIAN_KMS_CLIENT_ACCESS_TOKEN = "com.cosmian.kms.client.access.token";

    /**
     * The policy attributes to use for encrypt the data frame for instance:
     * 
     * <pre>
     * "Department::MKG, Confidentiality::HIGH"
     * </pre>
     */
    private static final Logger LOG = LoggerFactory.getLogger(CosmianAbeFactory.class);

    /**
     * The KMS Id of the user decryption key to use to decrypt the current data
     * frame
     */
    public static final String COSMIAN_DECRYPTION_KEY_ID = "cosmian.decryption.key.id";

    public static final String COSMIAN_ENCRYPTION_ATTRIBUTES = "cosmian.encryption.attributes";
    private static final ThreadLocal<KeyManagementService> kmsService = new ThreadLocal<KeyManagementService>() {

        @Override
        protected KeyManagementService initialValue() {
            return new KeyManagementService();
        }

    };

    public CosmianAbeFactory() {

        // System.out.println("CosmianEncryptionFactory instantiation on " +
        // Thread.currentThread().getName());
    }

    @Override
    public FileEncryptionProperties getFileEncryptionProperties(Configuration fileHadoopConfig, Path tempFilePath,
            WriteContext fileWriteContext) throws ParquetCryptoRuntimeException {

        // recover and parse the encryption attributes
        String[] attributeStrings = fileHadoopConfig.getStrings(COSMIAN_ENCRYPTION_ATTRIBUTES);
        if (attributeStrings == null) {
            LOG.debug("No Cosmian Encryption Policy Attributes provided. Ignoring encryption for {} at {}",
                    fileWriteContext.getSchema().getName(), tempFilePath.toString());
            return null;
        }
        Attr[] attributes;
        attributes = new Attr[attributeStrings.length];
        for (int i = 0; i < attributeStrings.length; i++) {
            try {
                attributes[i] = Attr.fromString(attributeStrings[i]);
            } catch (CosmianException e) {
                LOG.error("Invalid policy attribute {}: {}", attributeStrings[i], e.getMessage());
                throw new ParquetCryptoRuntimeException("Invalid policy attribute " + attributeStrings[i], e);
            }
        }

        // generate the symmetric key and its encryption
        Keys keys = kmsService.get().generateKeys(fileHadoopConfig, attributes);
        // The generated symmetric key is the footer key
        byte[] footerKeyBytes = keys.getClearTextKey();
        // ... and the meta_data is the actual encryption of the key
        byte[] footerKeyMetadata = keys.getEncryptedKey();

        LOG.trace("Encrypted {} with attributes {} ", tempFilePath, String.join(",", attributeStrings));

        ParquetCipher cipher = ParquetCipher.AES_GCM_V1;
        FileEncryptionProperties.Builder propertiesBuilder = FileEncryptionProperties.builder(footerKeyBytes)
                .withFooterKeyMetadata(footerKeyMetadata)
                .withAlgorithm(cipher);
        // .withEncryptedColumns(encryptedColumns);
        return propertiesBuilder.build();
    }

    @Override
    public FileDecryptionProperties getFileDecryptionProperties(Configuration hadoopConfig, Path filePath)
            throws ParquetCryptoRuntimeException {

        // System.out.println("Decrypting file: " + filePath);

        // Recover the decryption cache handle for the given public key
        String decryptionKeyId = hadoopConfig.get(COSMIAN_DECRYPTION_KEY_ID);
        if (decryptionKeyId == null) {
            LOG.debug("No Cosmian Decryption key provided. Ignoring decryption");
            return null;
        }

        FileDecryptionProperties.Builder propertiesBuilder = FileDecryptionProperties.builder()
                .withKeyRetriever(new DecryptionKeyRetriever() {

                    @Override
                    public byte[] getKey(byte[] keyMetaData)
                            throws KeyAccessDeniedException, ParquetCryptoRuntimeException {
                        try {
                            return kmsService.get().decryptSymmetricKey(hadoopConfig, decryptionKeyId, keyMetaData);
                        } catch (ParquetCryptoRuntimeException e) {
                            throw new ParquetCryptoRuntimeException(filePath + ": " + e.getMessage(), e);
                        }
                    }
                })
                .withPlaintextFilesAllowed();
        return propertiesBuilder.build();
    }

}
