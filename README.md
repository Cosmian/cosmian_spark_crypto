
## Encrypting Parquet partitions with Spark and access policy attributes

A [Spark](https://spark.apache.org/) add-on that enables Attribute Based Encryption in [Parquet](https://parquet.apache.org/) partitions using a single instruction.


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

The instruction above will encrypt the 2 dimensional partition `France x Marketing` with the access policy attributes `Country::France` and `Unit::Marketing`.


## Why use policy attributes when encrypting partitions ?

1. **Better security** through partitioning: leaking a decryption key only gives access to the partition(s) this key can decrypt.

2. Encryption is performed using a public key, which cannot decrypt and hence can be safely deployed to all encrypting system: **Encrypting systems do not need to be secured**.

3. The crypto system allows issuing user decryption keys for **overlapping set of partitions**, allowing for sophisticated, fine grained user access policies.

4. User decryptions keys can be issued at any time **after** data is encrypted, for any given set of partitions, which **facilitates user key management** and does not require exhaustively listing all possible usages prior to partitioning (a typical data science use case). 

5. The crypto system allows rotating policy attributes, providing **forward secrecy for designated partitions** without having to re-encrypt the full database.

Consider the following 2 policy axes, `Unit` and `Country` according to which data is partitioned:

1. `Unit`: `Finance`, `Marketing`, `Human Res.`, `Sales`
2. `Country`: `France`, `UK`, `Spain`, `Germany`

Each pair (`Unit`, `Country`) constitues one of the 16 data partitions.

- traditional symmetric encryption will have a single key for all partitions: leaking this key, leaks the entire database. There effectively is a single user: users cannot be differentiated. The same key is used to encrypt and decrypt requiring both the encrypting and decrypting systems to be secured.

- end to end encryption will have a single key for each partition: providing access to various users over combination of partitions leads to complex key management and duplicates keys among users, which is not a good security practice. The same keys are used to encrypt and decrypt, requiring both the encrypting and decrypting systems to be secured.

- with attribute based encryption, the encryption key is public - avoiding having to secure the encrypting systems - and each user can have its own unique key even though partitions overlap:

 Unit/Country  | France |   UK   |  Spain  |  Germany  |
 --------------|--------|--------|---------|-----------|
 **Finance**   |  K₁    |        |         |           |
 **Marketing** |  K₁    |        |    K₃   |    K₃     |
 **Human Res.**|  K₁    |        |         |           |
 **Sales**     |  K₁ K₂ |   K₂   |  K₂ K₃  |   K₂ K₃   |


Key `K₁` can decrypt all the `France` data with the following access policy
``` 
(Unit::Finance || Unit::Marketing || Unit::Human Res. || Unit::Sales ) && Country::France 
```

Key `K₂` can decrypt all the `Sales` data with the following access policy
``` 
Unit::Sales && (Country::France || Country::UK || Country::Spain || Country::Germany )
```

Key `K₃` can decrypt the `Marketing` and `Sales` data from `Spain` and `Germany` with the following access policy
``` 
(Unit::Marketing || Unit::Sales) && (Country::Spain || Country::Germany )
```

User keys are truly unique: 2 users having access to the same set of partitions, have different keys. This adds security as users can be individually traced.

For details on the underlying cryptographic protocol check the [abe_gpsw](https://github.com/Cosmian/abe_gpsw/) and [cosmian_java_lib](https://github.com/Cosmian/cosmian_java_lib) Github repositories.

## Performance

The system is built on top of [Parquet Modular Encryption](https://github.com/apache/parquet-format/blob/master/Encryption.md) and displays the same excellent performance on Spark 3.2.

Millions of records can be encrypted in a matter of seconds.


## Using


### Setup the Spark project

1. Add the two libraries to the the `sbt` dependencies

```scala
  libraryDependencies ++= Seq(
    ...
    "com.cosmian" % "cosmian_java_lib" % "0.6.2",
    "com.cosmian" %% "cosmian_spark_crypto" % "1.0.0",
    ...
  )
```

2. Download the abe_gpsw library from the github repository or build it according to these [instructions](https://github.com/Cosmian/cosmian_java_lib#building-the-the-abe-gpsw-native-lib) and install it in the `src/main/resources/linux-x86-64` of your spark project.  


### Generate the master keys

Using instructions available on the [cosmian_java_lib](https://github.com/Cosmian/cosmian_java_lib) Github repository, generate a master key pair for a partitioning policy.

 - the master public key can only be used to encrypt data, with any set of policy attributes. It can be safely deployed to any system encrypting data.

 - the master secret key is used to generate user decryption key with 





