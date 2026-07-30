using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Vectors;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

/// <summary>
/// 每个方法都处理同样的 1024 字节，对比不同批处理宽度与 BouncyCastle 单块实现
/// </summary>
[MemoryDiagnoser]
[RankColumn]
public class Sm4CipherBenchmark
{
	[Params(false, true)]
	public bool IsDecrypt { get; set; }

	private Sm4Cipher _cipher = default!;
	private BcSm4Cipher _bcCipher = default!;
	private byte[] _buffer = [];
	private VectorBuffer1024 _output;

	[GlobalSetup]
	public void Setup()
	{
		ReadOnlySpan<byte> key = RandomNumberGenerator.GetBytes(16);
		_cipher = Sm4Cipher.Create(key);
		_bcCipher = BcSm4Cipher.Create(key);
		_buffer = RandomNumberGenerator.GetBytes(64 * 16);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cipher.Dispose();
		_bcCipher.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void B1()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		ref VectorBuffer1024 output = ref _output;

		if (IsDecrypt)
		{
			for (int i = 0; i < 64 / 1; ++i)
			{
				ref readonly VectorBuffer16 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref source), i);
				ref VectorBuffer16 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref output), i);
				dst = _cipher.Decrypt(src);
			}
		}
		else
		{
			for (int i = 0; i < 64 / 1; ++i)
			{
				ref readonly VectorBuffer16 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref source), i);
				ref VectorBuffer16 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref output), i);
				dst = _cipher.Encrypt(src);
			}
		}
	}

	[Benchmark]
	public void B2()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		ref VectorBuffer1024 output = ref _output;

		if (IsDecrypt)
		{
			for (int i = 0; i < 64 / 2; ++i)
			{
				ref readonly VectorBuffer32 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer32>(ref source), i);
				ref VectorBuffer32 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer32>(ref output), i);
				dst = _cipher.Decrypt(src);
			}
		}
		else
		{
			for (int i = 0; i < 64 / 2; ++i)
			{
				ref readonly VectorBuffer32 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer32>(ref source), i);
				ref VectorBuffer32 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer32>(ref output), i);
				dst = _cipher.Encrypt(src);
			}
		}
	}

	[Benchmark]
	public void B4()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		ref VectorBuffer1024 output = ref _output;

		if (IsDecrypt)
		{
			for (int i = 0; i < 64 / 4; ++i)
			{
				ref readonly VectorBuffer64 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer64>(ref source), i);
				ref VectorBuffer64 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer64>(ref output), i);
				dst = _cipher.Decrypt(src);
			}
		}
		else
		{
			for (int i = 0; i < 64 / 4; ++i)
			{
				ref readonly VectorBuffer64 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer64>(ref source), i);
				ref VectorBuffer64 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer64>(ref output), i);
				dst = _cipher.Encrypt(src);
			}
		}
	}

	[Benchmark]
	public void B8()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		ref VectorBuffer1024 output = ref _output;

		if (IsDecrypt)
		{
			for (int i = 0; i < 64 / 8; ++i)
			{
				ref readonly VectorBuffer128 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer128>(ref source), i);
				ref VectorBuffer128 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer128>(ref output), i);
				dst = _cipher.Decrypt(src);
			}
		}
		else
		{
			for (int i = 0; i < 64 / 8; ++i)
			{
				ref readonly VectorBuffer128 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer128>(ref source), i);
				ref VectorBuffer128 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer128>(ref output), i);
				dst = _cipher.Encrypt(src);
			}
		}
	}

	[Benchmark]
	public void B16()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		ref VectorBuffer1024 output = ref _output;

		if (IsDecrypt)
		{
			for (int i = 0; i < 64 / 16; ++i)
			{
				ref readonly VectorBuffer256 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer256>(ref source), i);
				ref VectorBuffer256 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer256>(ref output), i);
				dst = _cipher.DecryptV256(src);
			}
		}
		else
		{
			for (int i = 0; i < 64 / 16; ++i)
			{
				ref readonly VectorBuffer256 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer256>(ref source), i);
				ref VectorBuffer256 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer256>(ref output), i);
				dst = _cipher.EncryptV256(src);
			}
		}
	}

	[Benchmark]
	public void BouncyCastle()
	{
		ref VectorBuffer1024 source = ref _buffer.As<byte, VectorBuffer1024>();
		ref VectorBuffer1024 output = ref _output;

		if (IsDecrypt)
		{
			for (int i = 0; i < 64; ++i)
			{
				ref readonly VectorBuffer16 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref source), i);
				ref VectorBuffer16 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref output), i);
				dst = _bcCipher.Decrypt(src);
			}
		}
		else
		{
			for (int i = 0; i < 64; ++i)
			{
				ref readonly VectorBuffer16 src = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref source), i);
				ref VectorBuffer16 dst = ref Unsafe.Add(ref Unsafe.As<VectorBuffer1024, VectorBuffer16>(ref output), i);
				dst = _bcCipher.Encrypt(src);
			}
		}
	}
}
