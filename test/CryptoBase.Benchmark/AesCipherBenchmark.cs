using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Vectors;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[RankColumn]
public class AesCipherBenchmark
{
	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	[Params(false, true)]
	public bool IsDecrypt { get; set; }

	private AesCipher _cipher = default!;
	private byte[] _buffer = [];

	[GlobalSetup]
	public void Setup()
	{
		ReadOnlySpan<byte> key = RandomNumberGenerator.GetBytes(KeyLength);
		_cipher = AesCipher.Create(key);
		_buffer = RandomNumberGenerator.GetBytes(64 * 16);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cipher.Dispose();
	}

	[Benchmark(Baseline = true)]
	public VectorBuffer1024 B1()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		Unsafe.SkipInit(out VectorBuffer1024 r);

		for (int i = 0; i < 64 / 1; ++i)
		{
			ref readonly VectorBuffer16 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref source), i);
			ref VectorBuffer16 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref r), i);
			dst = IsDecrypt ? _cipher.Decrypt(src) : _cipher.Encrypt(src);
		}

		return r;
	}

	[Benchmark]
	public VectorBuffer1024 B2()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		Unsafe.SkipInit(out VectorBuffer1024 r);

		for (int i = 0; i < 64 / 2; ++i)
		{
			ref readonly VectorBuffer32 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer32>(ref source), i);
			ref VectorBuffer32 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer32>(ref r), i);
			dst = IsDecrypt ? _cipher.Decrypt(src) : _cipher.Encrypt(src);
		}

		return r;
	}

	[Benchmark]
	public VectorBuffer1024 B4()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		Unsafe.SkipInit(out VectorBuffer1024 r);

		for (int i = 0; i < 64 / 4; ++i)
		{
			ref readonly VectorBuffer64 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer64>(ref source), i);
			ref VectorBuffer64 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer64>(ref r), i);
			dst = IsDecrypt ? _cipher.Decrypt(src) : _cipher.Encrypt(src);
		}

		return r;
	}

	[Benchmark]
	public VectorBuffer1024 B8()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		Unsafe.SkipInit(out VectorBuffer1024 r);

		for (int i = 0; i < 64 / 8; ++i)
		{
			ref readonly VectorBuffer128 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer128>(ref source), i);
			ref VectorBuffer128 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer128>(ref r), i);
			dst = IsDecrypt ? _cipher.Decrypt(src) : _cipher.Encrypt(src);
		}

		return r;
	}

	[Benchmark]
	public VectorBuffer1024 B16()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		Unsafe.SkipInit(out VectorBuffer1024 r);

		for (int i = 0; i < 64 / 16; ++i)
		{
			ref readonly VectorBuffer256 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer256>(ref source), i);
			ref VectorBuffer256 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer256>(ref r), i);
			dst = IsDecrypt ? _cipher.Decrypt(src) : _cipher.Encrypt(src);
		}

		return r;
	}

	[Benchmark]
	public VectorBuffer1024 B32()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		Unsafe.SkipInit(out VectorBuffer1024 r);

		for (int i = 0; i < 64 / 32; ++i)
		{
			ref readonly VectorBuffer512 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer512>(ref source), i);
			ref VectorBuffer512 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer512>(ref r), i);
			dst = IsDecrypt ? _cipher.Decrypt(src) : _cipher.Encrypt(src);
		}

		return r;
	}
}
