using CryptoBase.Benchmark.SymmetricCryptos.StreamCryptos;

namespace CryptoBase.Benchmark.SymmetricCryptos.BlockCryptoModes;

public abstract class BlockModeStreamCryptoBenchmarkBase : StreamCryptoBenchmarkBase
{
	public override IEnumerable<int> ByteLengths => [16, 128, 256, 512, 1024, 8192];
}
