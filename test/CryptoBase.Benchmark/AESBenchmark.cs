using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
[RankColumn]
public class AesBenchmark
{
	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	[Params(1024, 8192)]
	public int Length { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(Length);
		_randomKey = RandomNumberGenerator.GetBytes(KeyLength);
	}

	private void Encrypt<T>() where T : IBlock16Cipher<T>
	{
		using T cipher = T.Create(_randomKey);
		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> output = new byte[origin.Length];

		int count = origin.Length / (16 * 16);

		ref byte ptr = ref output.GetReference();

		for (int i = 0; i < count; ++i)
		{
			int offset = i * 16 * 16;
			VectorBuffer256 r = cipher.Encrypt(origin.Slice(offset).AsVectorBuffer256());
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref ptr, offset), r);
		}
	}

	[Benchmark(Baseline = true)]
	public void AesCipher()
	{
		Encrypt<AesCipher>();
	}

	[Benchmark]
	public void BcAesCipher()
	{
		Encrypt<BcAesCipher>();
	}
}
