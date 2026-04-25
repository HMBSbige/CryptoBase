using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[RankColumn]
public class VectorConstBench
{
	[Params(1, 10, 100)]
	public int Max { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		Span<byte> data = stackalloc byte[32];
		RandomNumberGenerator.Fill(data);
	}

	[Benchmark(Baseline = true)]
	public Vector256<byte> CreateEveryTime()
	{
		Vector256<byte> v = Vector256<byte>.Zero;

		for (int i = 0; i < Max; ++i)
		{
			v += Vector256.Create
			(
				(byte)5, 1, 12, 7, 3, 15, 0, 8,
				10, 2, 9, 14, 4, 6, 11, 13,
				25, 18, 22, 27, 31, 20, 21, 28,
				30, 16, 17, 24, 19, 23, 26, 29
			);
		}

		return v;
	}

	private static Vector256<byte> Shuffle32PropA => Vector256.Create
	(
		(byte)5, 1, 12, 7, 3, 15, 0, 8,
		10, 2, 9, 14, 4, 6, 11, 13,
		25, 18, 22, 27, 31, 20, 21, 28,
		30, 16, 17, 24, 19, 23, 26, 29
	);

	[Benchmark]
	public Vector256<byte> Property()
	{
		Vector256<byte> v = Vector256<byte>.Zero;

		for (int i = 0; i < Max; ++i)
		{
			v += Shuffle32PropA;
		}

		return v;
	}

	private static ReadOnlySpan<byte> Shuffle32SpanA =>
	[
		5, 1, 12, 7, 3, 15, 0, 8,
		10, 2, 9, 14, 4, 6, 11, 13,
		25, 18, 22, 27, 31, 20, 21, 28,
		30, 16, 17, 24, 19, 23, 26, 29
	];

	private static ref readonly Vector256<byte> ConstV => ref Unsafe.As<byte, Vector256<byte>>(ref Shuffle32SpanA.GetReference());

	[Benchmark]
	public Vector256<byte> FromConstArray()
	{
		Vector256<byte> v = Vector256<byte>.Zero;

		for (int i = 0; i < Max; ++i)
		{
			v += ConstV;
		}

		return v;
	}

	private static readonly Vector256<byte> Shuffle32A = Vector256.Create
	(
		(byte)5, 1, 12, 7, 3, 15, 0, 8,
		10, 2, 9, 14, 4, 6, 11, 13,
		25, 18, 22, 27, 31, 20, 21, 28,
		30, 16, 17, 24, 19, 23, 26, 29
	);

	[Benchmark]
	public Vector256<byte> StaticReadonly()
	{
		Vector256<byte> v = Vector256<byte>.Zero;

		for (int i = 0; i < Max; ++i)
		{
			v += Shuffle32A;
		}

		return v;
	}
}
