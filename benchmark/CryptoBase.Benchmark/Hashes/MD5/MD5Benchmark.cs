using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.MD5;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.MD5;

[MemoryDiagnoser]
public class MD5Benchmark : BclAndBouncyCastleHashBenchmark<MD5HashAlgorithm, BclMD5, MD5Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block64;
}
