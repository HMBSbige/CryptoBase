# Speed test

`cryptobase-speedtest` measures the speed of the [CryptoBase](https://github.com/HMBSbige/CryptoBase) algorithms on your machine. It is a .NET tool, so it needs the .NET SDK.

```shell
# Run it once without installing.
dnx CryptoBase.SpeedTest

# Or install it.
dotnet tool install -g CryptoBase.SpeedTest
```

## Usage

```shell
# Every algorithm but the slow ones.
cryptobase-speedtest

# Some algorithms: names, patterns with * and ?, or group names.
cryptobase-speedtest sha256 'aes-*' kem

# Input sizes of 1 KiB and 1 MiB, one second per cell, eight threads.
cryptobase-speedtest aead -b 1k 1m -s 1 -t 8

# Decryption instead of encryption.
cryptobase-speedtest aead --decrypt

# Markdown tables, or a JSON document.
cryptobase-speedtest hash -f markdown
cryptobase-speedtest hash -f json > hash.json
```

Algorithms that process data report MiB/s at each input size, and the others, such as signatures and key exchanges, operations per second. Slow algorithms, such as RSA key generation, run only when named or matched by a wildcard.

Each run starts with the runtime, the processor and the instruction sets in use, so include it when you share results.

## Other commands

```shell
# The algorithms with their groups and operations.
cryptobase-speedtest list

# The runtime, the processor and its instruction sets in full.
cryptobase-speedtest info

# Check every workload once instead of measuring.
cryptobase-speedtest --test

# Every option.
cryptobase-speedtest --help
```

## Native AOT

The tool runs on the JIT. To measure the speeds under Native AOT, publish `benchmark/CryptoBase.SpeedTest` from the source with `PublishAot`.
