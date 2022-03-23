package com.cosmian.spark;

import com.cosmian.CosmianException;
import com.cosmian.jna.Ffi;
import com.cosmian.jna.FfiException;
import com.cosmian.jna.abe.EncryptedHeader;
import com.cosmian.rest.abe.acccess_policy.Attr;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.crypto.EncryptionPropertiesFactory;
import org.apache.parquet.crypto.FileEncryptionProperties;
import org.apache.parquet.crypto.ParquetCipher;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.parquet.hadoop.api.WriteSupport.WriteContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptionPropertiesFactoryImpl implements EncryptionPropertiesFactory {

    /**
     * The handle of the encryption cache created with
     * {@link Ffi#createEncryptionCache(com.cosmian.rest.kmip.objects.PublicKey)}
     */
    public static final String COSMIAN_ENCRYPTION_CACHE_HANDLE = "cosmian.encryption.cache.handle";

    /**
     * The policy attributes to use for that file for instance:
     * 
     * <pre>
     * "Department::MKG, Confidentiality::HIGH"
     * </pre>
     */
    public static final String COSMIAN_ENCRYPTION_ATTRIBUTES = "cosmian.encryption.attributes";

    private static final Logger LOG = LoggerFactory.getLogger(EncryptionPropertiesFactoryImpl.class);

    @Override
    public FileEncryptionProperties getFileEncryptionProperties(Configuration fileHadoopConfig, Path tempFilePath,
            WriteContext fileWriteContext) throws ParquetCryptoRuntimeException {

        // Recover the encryption cache handle for the given public key
        int encryptionCacheHandle = fileHadoopConfig.getInt(COSMIAN_ENCRYPTION_CACHE_HANDLE, -1);
        if (encryptionCacheHandle == -1) {
            LOG.debug("No Cosmian Encryption cache handle available. Ignoring encryption for {} at {}",
                    fileWriteContext.getSchema().getName(), tempFilePath.toString());
            return null;
        }

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

        ParquetCipher cipher = ParquetCipher.AES_GCM_V1;
        EncryptedHeader header;
        try {
            header = Ffi.encryptHeaderUsingCache(encryptionCacheHandle, attributes);
        } catch (FfiException | CosmianException e) {
            LOG.error("Header encryption failed: {}", e.getMessage());
            throw new ParquetCryptoRuntimeException("Header encryption failed: " + e.getMessage(), e);
        }

        // The generated symmetric key is the footer key
        byte[] footerKeyBytes = header.getSymmetricKey();
        // ... and the meta_data is the actual encryption of the key
        byte[] footerKeyMetadata = header.getEncryptedHeaderBytes();

        FileEncryptionProperties.Builder propertiesBuilder = FileEncryptionProperties.builder(footerKeyBytes)
                .withFooterKeyMetadata(footerKeyMetadata)
                .withAlgorithm(cipher);
        // .withEncryptedColumns(encryptedColumns);
        return propertiesBuilder.build();
    }

}
