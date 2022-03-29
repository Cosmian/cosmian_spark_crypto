
## Encrypting Parquet partitions with Spark and access policy attributes

A [Spark](https://spark.apache.org/) add-on that enables Attribute Based Encryption in Parquet partitions using a single instruction.


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

For details on the underlying cryptographic protocol - attributes based encryption - check the [abe_gpsw](https://github.com/Cosmian/abe_gpsw/) and [cosmian_java_lib](https://github.com/Cosmian/cosmian_java_lib) Github repositories.


## Why use policy attributes when encrypting Parquet partitions ?

1. Better security through partitioning: leaking a decryption key only gives access to the partition(s) this key can decrypt.

2. Encryption is performed using a public key, which can be safely deployed to all encrypting system, as it cannot decrypt data.

3. The crypto system allows, after encryption, to issue decryption keys for overlapping partitions, facilitating access management to the data.

4. The crypto system allows rotating policy attributes, providing forward secrecy for designated partitions.

Consider the following policy axes, `Unit` and `Country` according to which data is partitioned and encrypted:


 Unit/Country  | France |   UK   |  Spain  |  Germany  |
 --------------|--------|--------|---------|-----------|
 **Finance**   |  K₁ K₂ |   K₂   |    K₂   |    K₂     |
 **Marketing** |  K₁    |        |    K₃   |    K₃     |
 **Human Res.**|  K₁    |        |         |           |
 **Sales**     |  K₁    |        |    K₃   |    K₃     |


Key `K₁` can decrypt all the `France` data and has the following access policy
``` 
(Unit::Finance || Unit::Marketing || Unit::Human Res. || Unit::Sales ) && Country::France 
```

Key `K₂` can decrypt all the `Finance` and has the following access policy
``` 
Unit::Finance && (Country::France || Country::UK || Country::Spain || Country::Germany )
```

Key `K₃` can decrypt the `Marketing` and `Sales` data from `Spain` and `Germany` and has the following access policy
``` 
(Unit::Marketing || Unit::Sales) && (Country::Spain || Country::Germany )
```

## Performance

The system is built on top of [Parquet Modular Encryption](https://github.com/apache/parquet-format/blob/master/Encryption.md) and displays the same excellent performance on Spark 3.2.

Millions of records can be encrypted in a matter of seconds.


## Using

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


3. Encryption




