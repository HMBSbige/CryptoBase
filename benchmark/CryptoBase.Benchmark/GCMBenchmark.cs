using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class GCMBenchmark
{
	[Params(1024, 8192, 16384)]
	public int ByteLength { get; set; }

	private IAEADCrypto _managedAes = null!;
	private IAEADCrypto? _dotNetAes;
	private IAEADCrypto _bcAes = null!;
	private IAEADCrypto _managedSm4 = null!;

	private byte[] _input = [];
	private byte[] _output = [];
	private byte[] _nonce = [];
	private byte[] _tag = [];

	[GlobalSetup]
	public void Setup()
	{
		byte[] key = RandomNumberGenerator.GetBytes(16);

		_managedAes = new GcmMode128<AesCipher>(AesCipher.Create(key));
		_dotNetAes = DefaultAesGcmCrypto.IsSupported ? new DefaultAesGcmCrypto(key) : default;
		_bcAes = new BcAesGcmCrypto(key);
		_managedSm4 = new GcmMode128<Sm4Cipher>(Sm4Cipher.Create(key));

		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_output = new byte[ByteLength];
		_nonce = RandomNumberGenerator.GetBytes(12);
		_tag = new byte[16];
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_managedAes.Dispose();
		_dotNetAes?.Dispose();
		_bcAes.Dispose();
		_managedSm4.Dispose();
	}

	private void Encrypt(IAEADCrypto crypto)
	{
		crypto.Encrypt(_nonce, _input, _output, _tag);
	}

	[Benchmark(Baseline = true)]
	public void Managed()
	{
		Encrypt(_managedAes);
	}

	[Benchmark]
	public void DotNet()
	{
		Encrypt(_dotNetAes ?? throw new NotSupportedException());
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Encrypt(_bcAes);
	}

	[Benchmark]
	public void ManagedSm4()
	{
		Encrypt(_managedSm4);
	}
}
