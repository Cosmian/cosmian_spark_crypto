![workflow](https://github.com/Cosmian/cosmian_spark_crypto/actions/workflows/maven.yml/badge.svg)

## Encrypting Parquet partitions with Spark and access policy attributes

A [Spark](https://spark.apache.org/) add-on that enables Attribute-Based Encryption in [Parquet](https://parquet.apache.org/) partitions using a single instruction.


```java
dataFrame
    .filter((col("COUNTRY") === "FR") && (col("UNIT") !== "MKG"))
    .write
    .mode(SaveMode.Append)
    .partitionBy("COUNTRY", "UNIT")
    .option(
        CosmianAbeFactory.COSMIAN_ENCRYPTION_ATTRIBUTES,
        "Country::France, Unit::Marketing"
    )
    .parquet(outputURI)
```

The instruction above will encrypt the 2-dimensional partition `France x Marketing` with the access policy attributes `Country::France` and `Unit::Marketing`.


## Why you should encrypt partitions using policy attributes

1. **Better security** through partitioning: leaking a decryption key only gives access to the partition(s) this key can decrypt.

2. Encryption is performed using a public key, which cannot decrypt and can therefore be safely deployed to all encrypting systems: **Encrypting systems do not need to be secured**.

3. The cryptosystem allows issuing user decryption keys for **overlapping sets of partitions**, allowing for sophisticated, fine-grained user access policies.

4. User decryptions keys can be issued at any time **after** data is encrypted, for any given set of partitions. This **facilitates user key management** and does not require exhaustively listing all possible usages before partitioning (a typical data science use case). 

5. The cryptosystem allows rotating policy attributes, providing **forward secrecy for designated partitions** without re-encrypting the entire database.

Consider the following 2 policy axes, `Unit` and `Country` according to which data is partitioned:

1. `Unit`: `Finance`, `Marketing`, `Human Res.`, `Sales`
2. `Country`: `France`, `UK`, `Spain`, `Germany`

Each pair (`Unit`, `Country`) constitutes one of the 16 data partitions.

- traditional symmetric encryption will have a single key for all partitions: leaking this key means leaking the entire database. There effectively is a single user: users cannot be differentiated. The same key encrypts and decrypts, requiring both the encrypting and decrypting systems to be secured.

- end-to-end encryption will have a single key for each partition: providing access to various users over combinations of partitions leads to complex key management and duplicated keys among users, which is not a good security practice. The same keys encrypt and decrypt, requiring both the encrypting and decrypting systems to be secured.

- with attribute-based encryption, the encryption key is public - avoiding having to secure the encrypting systems - and each user can have its own unique key even though partitions overlap:

 Unit/Country  | France |   UK   |  Spain  |  Germany  |
 --------------|--------|--------|---------|-----------|
 **Finance**   |  K???    |        |         |           |
 **Marketing** |  K???    |        |    K???   |    K???     |
 **Human Res.**|  K???    |        |         |           |
 **Sales**     |  K??? K??? |   K???   |  K??? K???  |   K??? K???   |


Key `K???` can decrypt all the `France` data with the following access policy
``` 
(Unit::Finance || Unit::Marketing || Unit::Human Res. || Unit::Sales ) && Country::France 
```

Key `K???` can decrypt all the `Sales` data with the following access policy
``` 
Unit::Sales && (Country::France || Country::UK || Country::Spain || Country::Germany )
```

Key `K???` can decrypt the `Marketing` and `Sales` data from `Spain` and `Germany` with the following access policy
``` 
(Unit::Marketing || Unit::Sales) && (Country::Spain || Country::Germany )
```

**User keys are truly unique**: 2 users having access to the same set of partitions, have different keys. This adds security as users can be individually tracked.

Lastly, **policies can be hierarchical**. Suppose you have three levels of classification: `Confidential`, `Secret`, and `Top Secret`. You can create a hierarchical policy that will let users with a `Top Secret` key decrypt `Confidential`, `Secret`, and `Top Secret` data ??? whereas users with a `Confidential` key will only be able to decrypt `Confidential` data.

For details on the underlying cryptographic protocol check the [abe_gpsw](https://github.com/Cosmian/abe_gpsw/) and [cosmian_java_lib](https://github.com/Cosmian/cosmian_java_lib) Github repositories.

## Performance

The system is built on top of [Parquet Modular Encryption](https://github.com/apache/parquet-format/blob/master/Encryption.md) and displays the same excellent performance on Spark 3.2.

Encryption of millions of records only takes a matter of seconds.


## Using


### Setup the Spark project

1. Add the two libraries to the `sbt` dependencies

```scala
  libraryDependencies ++= Seq(
    ...
    "com.cosmian" % "cosmian_java_lib" % "0.6.2",
    "com.cosmian" %% "cosmian_spark_crypto" % "1.0.0",
    ...
  )
```

2. Download the abe_gpsw library from the Github repository or build it according to these [instructions](https://github.com/Cosmian/cosmian_java_lib#building-the-the-abe-gpsw-native-lib) and install it in the `src/main/resources/linux-x86-64` of your spark project.  


### Generate the master keys

Using instructions available on the [cosmian_java_lib](https://github.com/Cosmian/cosmian_java_lib) Github repository, generate a master key pair for a partitioning policy.

 - the master public key can only be used to encrypt data, with any set of policy attributes. It can be safely deployed to any system encrypting data.

 - the master secret key is used to generate user decryption keys with the various access policies.

### Implement the KMS access

To fetch the public and user keys to respectively encrypt and decrypt data, Spark must communicate with your KMS.

Implement the interface `com.cosmian.spark` in your Spark project and pass the implementing class name to the Hadoop config using 

``` java
spark.sparkContext.hadoopConfiguration.set(
  CosmianAbeFactory.COSMIAN_KMS_CLIENT_CLASS,
  "com.company.YourKms"
)
```

Before retrieving any key using the `retrievePublicKey()` or `retrievePrivateKey(String privateKeyId)`, Spark will call the `initialize(Configuration configuration, String kmsInstanceID, String kmsInstanceURL, String accessToken)` method once per Spark thread.

The parameters passed to the `initialize` method are extracted from the parameters set on the Hadoop configuration of the Spark session.

 - `kmsInstanceId` :

    ``` java
    spark.sparkContext.hadoopConfiguration
      .set(
        CosmianAbeFactory.COSMIAN_KMS_CLIENT_INSTANCE_ID,
        "my.kms.instance.id"
      )
    ```

- `kmsInstanceURL` :

    ``` java
    spark.sparkContext.hadoopConfiguration
      .set(
        CosmianAbeFactory.COSMIAN_KMS_CLIENT_INSTANCE_ID,
        "http://kms.url/endpoint"
      )
    ```

- `accessToken`

    ``` java
    spark.sparkContext.hadoopConfiguration
      .set(
        CosmianAbeFactory.COSMIAN_KMS_CLIENT_ACCESS_TOKEN,
        "ae34bf56c..."
      )
    ```

Finally activate the Parquet modular encryption using


``` java
spark.sparkContext.hadoopConfiguration
  .set(
    "parquet.crypto.factory.class",
    "com.cosmian.spark.CosmianAbeFactory"
  )
```

Note: if you plan on using Cosmian Public Confidential KMS service, please contact us for details.

### Encryption

Simply pass the policy attributes using an `option` and the `CosmianAbeFactory.COSMIAN_ENCRYPTION_ATTRIBUTES`.

```java
dataFrame
    .filter((col("COUNTRY") === "FR") && (col("UNIT") !== "MKG"))
    .write
    .mode(SaveMode.Append)
    .partitionBy("COUNTRY", "UNIT")
    .option(
        CosmianAbeFactory.COSMIAN_ENCRYPTION_ATTRIBUTES,
        "Country::France, Unit::Marketing"
    )
    .parquet(outputURI)
```

Spark will generate the Parquet partition (on `COUNTRY` and `UNIT`) in which the footer and all columns are encrypted using the given attributes.


### Decryption

Set the decryption key on the Hadoop Configuration of the Spark session

``` java
spark.sparkContext.hadoopConfiguration
  .set(
    CosmianAbeFactory.COSMIAN_DECRYPTION_KEY_ID,
    "kmsDecryptionKeyId"
  )
```

then simply read the Parquet partition which will be decrypted on the fly:

``` java
spark.read
  .parquet(inputURI)
  .filter((col("COUNTRY") === "FR") && (col("UNIT") !== "MKG"))
```
