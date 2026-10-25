using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Sha3;

// One-shot HashData against an instance reused through Append and GetHashAndReset, over inputs that fit one block.
[MemoryDiagnoser]
[GenericTypeArguments(typeof(Sha3_224Core))]
[GenericTypeArguments(typeof(Sha3_256Core))]
[GenericTypeArguments(typeof(Sha3_384Core))]
[GenericTypeArguments(typeof(Sha3_512Core))]
public class Sha3ShortInputBenchmark<TCore> where TCore : unmanaged, IHashCore<TCore>
{
	[Params(0, 20, 32, 64)]
	public int ByteLength { get; set; }

	private byte[] _input = [];
	private byte[] _hash = [];
	private HashAlgorithm<TCore> _hasher = HashAlgorithm<TCore>.Create();

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_hash = new byte[HashAlgorithm<TCore>.HashLength];
		_hasher = HashAlgorithm<TCore>.Create();

		Incremental();
		byte[] expected = (byte[])_hash.Clone();
		OneShot();
		Verify(expected, _hash);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_hasher.Dispose();
	}

	[Benchmark(Baseline = true)]
	public int OneShot()
	{
		return HashAlgorithm<TCore>.HashData(_input, _hash);
	}

	[Benchmark]
	public int Incremental()
	{
		_hasher.Append(_input);
		return _hasher.GetHashAndReset(_hash);
	}

	private static void Verify(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
	{
		if (!CryptographicOperations.FixedTimeEquals(expected, actual))
		{
			throw new InvalidOperationException("One-shot and incremental hashing produced different output.");
		}
	}
}

// The XOF counterpart of Sha3ShortInputBenchmark, with a 32-byte output.
[MemoryDiagnoser]
[GenericTypeArguments(typeof(Shake128Core))]
[GenericTypeArguments(typeof(Shake256Core))]
public class ShakeShortInputBenchmark<TCore> where TCore : unmanaged, IXofCore<TCore>
{
	private const int OutputLength = 32;

	[Params(0, 20, 32, 64)]
	public int ByteLength { get; set; }

	private byte[] _input = [];
	private readonly byte[] _output = new byte[OutputLength];
	private Xof<TCore> _xof = Xof<TCore>.Create();

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(ByteLength);
		_xof = Xof<TCore>.Create();

		Incremental();
		byte[] expected = (byte[])_output.Clone();
		OneShot();
		Verify(expected, _output);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_xof.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void OneShot()
	{
		Xof<TCore>.HashData(_input, _output);
	}

	[Benchmark]
	public void Incremental()
	{
		_xof.Append(_input);
		_xof.GetHashAndReset(_output);
	}

	private static void Verify(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
	{
		if (!CryptographicOperations.FixedTimeEquals(expected, actual))
		{
			throw new InvalidOperationException("One-shot and incremental hashing produced different output.");
		}
	}
}
