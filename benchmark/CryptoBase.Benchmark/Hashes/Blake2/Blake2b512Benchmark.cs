using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Blake2;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Blake2;

[MemoryDiagnoser]
public class Blake2b512Benchmark : BouncyCastleHashBenchmark<Blake2b512Core, Blake2bDigest>
{
	protected override IReadOnlyList<int> Sizes { get; } = [0, 1, 64, 127, 128, 129, 256, 1024, 8192, 1024 * 1024];
}
