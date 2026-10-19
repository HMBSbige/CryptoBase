using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes;

public readonly record struct XofLengths(int InputLength, int OutputLength)
{
	public override string ToString()
	{
		return $"{InputLength}->{OutputLength}";
	}
}

public interface IBclXof
{
	// SHAKE depends on the platform's cryptographic library, which on macOS lacks it.
	static virtual bool IsSupported => true;

	static abstract void HashData(ReadOnlySpan<byte> source, Span<byte> destination);
}

// Inputs of AbsorbLengths with a 32-byte output time absorbing, and outputs of up to 1 MiB from a 32-byte input time squeezing.
public abstract class XofBenchmark<TCryptoBase, TBcl, TBouncyCastle>
	where TCryptoBase : unmanaged, IXofCore<TCryptoBase>
	where TBcl : IBclXof
	where TBouncyCastle : IXof, new()
{
	private const int ShortLength = 32;

	private static IReadOnlyList<int> OutputLengths => [64, 1024, 8192, 1024 * 1024];

	[ParamsSource(nameof(LengthValues))]
	public XofLengths Lengths { get; set; }

	public IEnumerable<XofLengths> LengthValues => AbsorbLengths.Select(static length => new XofLengths(length, ShortLength))
		.Concat(OutputLengths.Select(static length => new XofLengths(ShortLength, length)));

	protected abstract IReadOnlyList<int> AbsorbLengths { get; }

	private byte[] _input = [];
	private byte[] _output = [];
	private TBouncyCastle _bouncyCastle = default!;

	[GlobalSetup]
	public void Setup()
	{
		_bouncyCastle = new TBouncyCastle();
		_input = RandomNumberGenerator.GetBytes(Lengths.InputLength);
		_output = new byte[Lengths.OutputLength];

		BouncyCastle();
		byte[] expected = (byte[])_output.Clone();
		CryptoBase();
		Verify(expected);

		// Where the platform lacks the algorithm, Bcl throws PlatformNotSupportedException and reports no result, while the other columns still run.
		if (TBcl.IsSupported)
		{
			Bcl();
			Verify(expected);
		}
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		Xof<TCryptoBase>.HashData(_input, _output);
	}

	[Benchmark]
	public void Bcl()
	{
		TBcl.HashData(_input, _output);
	}

	[Benchmark]
	public int BouncyCastle()
	{
		_bouncyCastle.BlockUpdate(_input);
		return _bouncyCastle.OutputFinal(_output);
	}

	private void Verify(ReadOnlySpan<byte> expected)
	{
		if (!CryptographicOperations.FixedTimeEquals(expected, _output))
		{
			throw new InvalidOperationException("Benchmark implementations produced different output.");
		}
	}
}
