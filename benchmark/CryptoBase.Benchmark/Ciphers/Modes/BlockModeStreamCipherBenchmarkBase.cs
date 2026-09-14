using CryptoBase.Benchmark.Ciphers.Streams;

namespace CryptoBase.Benchmark.Ciphers.Modes;

public abstract class BlockModeStreamCipherBenchmarkBase : StreamCipherBenchmarkBase
{
	public override IEnumerable<int> ByteLengths => [16, 128, 256, 512, 1024, 8192];
}
