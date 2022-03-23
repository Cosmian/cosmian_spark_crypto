package com.cosmian.spark;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.crypto.EncryptionPropertiesFactory;
import org.apache.parquet.crypto.FileEncryptionProperties;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.parquet.hadoop.api.WriteSupport.WriteContext;

public class EncryptionPropertiesFactoryImpl implements EncryptionPropertiesFactory {

    @Override
    public FileEncryptionProperties getFileEncryptionProperties(Configuration fileHadoopConfig, Path tempFilePath,
            WriteContext fileWriteContext) throws ParquetCryptoRuntimeException {

        FileEncryptionProperties.Builder propertiesBuilder = FileEncryptionProperties.builder(footerKeyBytes)
                .withFooterKeyMetadata(footerKeyMetadata)
                .withAlgorithm(cipher)
                .withEncryptedColumns(encryptedColumns);
        return propertiesBuilder.build();
    }

}
