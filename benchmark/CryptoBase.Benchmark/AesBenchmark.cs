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
	[Params(1, 4, 8)]
	public int Block { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(1024);
		_randomKey = RandomNumberGenerator.GetBytes(16);
	}

	private void Encrypt<T>() where T : IBlock16Cipher<T>
	{
		using T cipher = T.Create(_randomKey);
		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> output = new byte[origin.Length];

		int count = origin.Length / (Block * 16);

		ref byte ptr = ref output.GetReference();

		for (int i = 0; i < count; ++i)
		{
			int offset = i * Block * 16;

			switch (Block)
			{
				case 1:
				{
					VectorBuffer16 r = cipher.Encrypt(origin.Slice(offset).AsVectorBuffer16());
					Unsafe.WriteUnaligned(ref Unsafe.Add(ref ptr, offset), r);
					continue;
				}
				case 4:
				{
					VectorBuffer64 r = cipher.Encrypt(origin.Slice(offset).AsVectorBuffer64());
					Unsafe.WriteUnaligned(ref Unsafe.Add(ref ptr, offset), r);
					continue;
				}
				case 8:
				{
					VectorBuffer128 r = cipher.Encrypt(origin.Slice(offset).AsVectorBuffer128());
					Unsafe.WriteUnaligned(ref Unsafe.Add(ref ptr, offset), r);
					continue;
				}
			}
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
