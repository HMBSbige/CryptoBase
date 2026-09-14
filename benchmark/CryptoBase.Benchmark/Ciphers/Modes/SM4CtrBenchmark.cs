using BenchmarkDotNet.Attributes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Ciphers.Modes;

[MemoryDiagnoser]
public class SM4CtrBenchmark : BlockModeStreamCipherBenchmarkBase
{
	private CtrMode128<SM4Cipher> _cryptoBase = null!;
	private SicBlockCipher _bouncyCastle = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		byte[] iv = RandomNumberGenerator.GetBytes(16);
		_cryptoBase = Register(CtrMode128<SM4Cipher>.Create(key, iv));
		_bouncyCastle = new SicBlockCipher(new SM4Engine());
		_bouncyCastle.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Run(_cryptoBase);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		for (int offset = 0; offset < Input.Length; offset += 16)
		{
			_bouncyCastle.ProcessBlock(Input.Slice(offset, 16), Output.Slice(offset, 16));
		}
	}
}
