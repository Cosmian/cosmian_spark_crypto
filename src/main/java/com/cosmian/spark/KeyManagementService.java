package com.cosmian.spark;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

import com.cosmian.CosmianException;
import com.cosmian.jna.Ffi;
import com.cosmian.jna.FfiException;
import com.cosmian.jna.abe.EncryptedHeader;
import com.cosmian.rest.abe.acccess_policy.Attr;
import com.cosmian.rest.abe.policy.Policy;
import com.cosmian.rest.kmip.objects.PrivateKey;
import com.cosmian.rest.kmip.objects.PublicKey;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;

class KeyManagementService {

    private Optional<Integer> publicKeyCacheHandle;
    private final HashMap<String, Integer> privateKeyCache;
    private KmsClient kmsClient;

    // avoid initialization race conditions
    private final ReentrantLock lock;

    public KeyManagementService() {
        this.publicKeyCacheHandle = Optional.empty();
        this.privateKeyCache = new HashMap<>();
        this.kmsClient = null;
        this.lock = new ReentrantLock();
        // System.out.println("Initializing KMS Service on thread " +
        // Thread.currentThread().getName());
    }

    /**
     * Make sure that the KMS Service is initialized
     * 
     * @param hadoopConfig the configuration
     * @throws ParquetCryptoRuntimeException if the {@link KmsClient} cannot be
     *                                       instantiated
     */
    private void ensureInitialized(Configuration hadoopConfig) throws ParquetCryptoRuntimeException {

        // avoid race conditions on initializations
        this.lock.lock();
        try {

            if (this.kmsClient != null) {
                // already initialized
                return;
            }

            String kmsClientClassName = hadoopConfig.get(CosmianAbeFactory.COSMIAN_KMS_CLIENT_CLASS);
            if (kmsClientClassName == null) {
                throw new ParquetCryptoRuntimeException(
                        "No KMS Client class specified using " + CosmianAbeFactory.COSMIAN_KMS_CLIENT_CLASS);
            }
            try {
                @SuppressWarnings("unchecked")
                Class<KmsClient> kmsClass = (Class<KmsClient>) Class.forName(kmsClientClassName);
                this.kmsClient = kmsClass.getDeclaredConstructor().newInstance();
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | IllegalArgumentException
                    | InvocationTargetException | NoSuchMethodException | SecurityException e) {
                throw new ParquetCryptoRuntimeException("Failed instantiating the KMS Client: " + e.getMessage(), e);
            }

            // initialize the KMS Client
            this.kmsClient.initialize(hadoopConfig,
                    hadoopConfig.get(CosmianAbeFactory.COSMIAN_KMS_CLIENT_INSTANCE_ID),
                    hadoopConfig.get(CosmianAbeFactory.COSMIAN_KMS_CLIENT_URL),
                    hadoopConfig.get(CosmianAbeFactory.COSMIAN_KMS_CLIENT_ACCESS_TOKEN));

        } finally {
            this.lock.unlock();
        }

    }

    /**
     * Generate a symmetric key and its ABE encryption for the given attributes
     * 
     * @param hadoopConfig the configuration
     * @param attributes   the policy attributes
     * @return the pair, clear text key, encrypted key
     * @throws ParquetCryptoRuntimeException if the key cannot be encrypted or the
     *                                       Kms Client fails
     */
    public Keys generateKeys(Configuration hadoopConfig, Attr[] attributes) throws ParquetCryptoRuntimeException {

        ensureInitialized(hadoopConfig);

        int publicKeyCacheHandle;
        // create an encryption cache if need be
        if (this.publicKeyCacheHandle.isEmpty()) {
            PublicKey publicKey;
            try {
                publicKey = PublicKey
                        .fromJson(new String(this.kmsClient.retrievePublicKey(), StandardCharsets.UTF_8));
            } catch (CosmianException e) {
                throw new ParquetCryptoRuntimeException(
                        "Failed recovering the public key from the bytes: " + e.getMessage(), e);
            }
            try {
                publicKeyCacheHandle = Ffi.createEncryptionCache(Policy.fromVendorAttributes(publicKey.attributes()),
                        publicKey.bytes());
            } catch (FfiException | CosmianException e) {
                throw new ParquetCryptoRuntimeException(
                        "Failed creating the public cache for the public key: " + e.getMessage(), e);

            }
            this.publicKeyCacheHandle = Optional.of(publicKeyCacheHandle);
        } else {
            publicKeyCacheHandle = this.publicKeyCacheHandle.get();
        }

        // perform the key generation and encryption
        EncryptedHeader header;
        try {
            header = Ffi.encryptHeaderUsingCache(publicKeyCacheHandle, attributes);
        } catch (FfiException | CosmianException e) {
            throw new ParquetCryptoRuntimeException("Header encryption failed: " + e.getMessage(), e);
        }
        return new Keys(header.getSymmetricKey(), header.getEncryptedHeaderBytes());
    }

    public byte[] decryptSymmetricKey(Configuration hadoopConfig, String privateKeyId, byte[] encryptedKey)
            throws ParquetCryptoRuntimeException {

        ensureInitialized(hadoopConfig);

        Integer privateKeyCacheHandle = this.privateKeyCache.get(privateKeyId);
        // create an encryption cache if need be
        if (privateKeyCacheHandle == null) {
            PrivateKey privateKey;
            try {
                privateKey = PrivateKey
                        .fromJson(new String(this.kmsClient.retrievePrivateKey(privateKeyId), StandardCharsets.UTF_8));
            } catch (CosmianException e) {
                throw new ParquetCryptoRuntimeException(
                        "Failed recovering the private key '" + privateKeyId + "'' from the bytes: " + e.getMessage(),
                        e);
            }
            try {
                privateKeyCacheHandle = Ffi.createDecryptionCache(privateKey.bytes());
            } catch (FfiException | CosmianException e) {
                throw new ParquetCryptoRuntimeException(
                        "Failed creating the private cache for the private key '" + privateKeyId + "'': "
                                + e.getMessage(),
                        e);

            }
            this.privateKeyCache.put(privateKeyId, privateKeyCacheHandle);
        }

        try {
            return Ffi.decryptHeaderUsingCache(privateKeyCacheHandle, encryptedKey).getSymmetricKey();
        } catch (FfiException | CosmianException e) {
            throw new ParquetCryptoRuntimeException(
                    "Symmetric key decryption using the private key '" + privateKeyId + "', failed: " + e.getMessage(),
                    e);
        }
    }

}
