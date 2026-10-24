using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Sha3;

public interface ICShake
{
	// The security strength that selects the rate of BouncyCastle's CShakeDigest.
	static abstract int SecurityStrength { get; }

	static abstract void HashData(ReadOnlySpan<byte> source, Span<byte> destination);

	static abstract void HashData(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination);
}

public readonly struct CryptoBaseCShake128 : ICShake
{
	public static int SecurityStrength => 128;

	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShake128Xof.HashData(source, destination);
	}

	public static void HashData(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShake128Xof.HashData(functionName, customization, source, destination);
	}
}

public readonly struct CryptoBaseCShake256 : ICShake
{
	public static int SecurityStrength => 256;

	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShake256Xof.HashData(source, destination);
	}

	public static void HashData(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShake256Xof.HashData(functionName, customization, source, destination);
	}
}

// One-shot cSHAKE of the input lengths of the rate to a 32-byte output. With a customization string, against BouncyCastle; with an empty function name and customization string, which is SHAKE (SP 800-185, Sec. 3.3), against Xof over the SHAKE core of the same rate.
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public abstract class CShakeBenchmark<TCShake, TShake> where TCShake : ICShake where TShake : unmanaged, IXofCore<TShake>
{
	private const int OutputLength = 32;
	private const string CustomizedCategory = "Customized";
	private const string UncustomizedCategory = "Uncustomized";

	// The customization string of the NIST cSHAKE samples.
	private static ReadOnlySpan<byte> Customization => "Email Signature"u8;

	[ParamsSource(nameof(InputLengths))]
	public int InputLength { get; set; }

	public IEnumerable<int> InputLengths => Sizes;

	protected abstract IReadOnlyList<int> Sizes { get; }

	private byte[] _input = [];
	private byte[] _output = [];
	private readonly CShakeDigest _bouncyCastle = new(TCShake.SecurityStrength, [], Customization.ToArray());

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(InputLength);
		_output = new byte[OutputLength];

		BouncyCastle();
		Verify((byte[])_output.Clone(), CryptoBase);

		Shake();
		Verify((byte[])_output.Clone(), CryptoBaseUncustomized);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory(CustomizedCategory)]
	public void CryptoBase()
	{
		TCShake.HashData(ReadOnlySpan<byte>.Empty, Customization, _input, _output);
	}

	[Benchmark]
	[BenchmarkCategory(CustomizedCategory)]
	public int BouncyCastle()
	{
		_bouncyCastle.BlockUpdate(_input);
		return _bouncyCastle.OutputFinal(_output);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory(UncustomizedCategory)]
	public void Shake()
	{
		Xof<TShake>.HashData(_input, _output);
	}

	[Benchmark]
	[BenchmarkCategory(UncustomizedCategory)]
	public void CryptoBaseUncustomized()
	{
		TCShake.HashData(_input, _output);
	}

	// Clears the output first, so that an implementation that writes nothing cannot pass on what the previous one left behind.
	private void Verify(ReadOnlySpan<byte> expected, Action implementation)
	{
		_output.AsSpan().Clear();
		implementation();

		if (!CryptographicOperations.FixedTimeEquals(expected, _output))
		{
			throw new InvalidOperationException("Benchmark implementations produced different output.");
		}
	}
}
