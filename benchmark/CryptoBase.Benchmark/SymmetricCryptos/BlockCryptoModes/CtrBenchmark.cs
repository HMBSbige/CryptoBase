using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.SymmetricCryptos.BlockCryptoModes;

[MemoryDiagnoser]
public class AesCtrBenchmark : BlockModeStreamCryptoBenchmarkBase
{
	private IStreamCrypto _cryptoBase = null!;
	private SicBlockCipher _bouncyCastle = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		byte[] iv = RandomNumberGenerator.GetBytes(16);
		_cryptoBase = Register(StreamCryptoCreate.AesCtr(key, iv));
		_bouncyCastle = new SicBlockCipher(AesUtilities.CreateEngine());
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

[MemoryDiagnoser]
public class SM4CtrBenchmark : BlockModeStreamCryptoBenchmarkBase
{
	private IStreamCrypto _cryptoBase = null!;
	private SicBlockCipher _bouncyCastle = null!;

	protected override void SetupCryptos()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);
		byte[] iv = RandomNumberGenerator.GetBytes(16);
		_cryptoBase = Register(StreamCryptoCreate.SM4Ctr(key, iv));
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
