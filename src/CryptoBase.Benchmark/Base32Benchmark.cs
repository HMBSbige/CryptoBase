using BenchmarkDotNet.Attributes;
using CryptoBase.DataFormatExtensions;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class Base32Benchmark
{
	[Params(1)]
	public int Max { get; set; }

	private const string BaseStr = @"HEZDKMZWG4YDILJRMYYDOLJUHA2TMLJYHFQTILLCGBRDKOJSMZSWCMBRMM======";

	private static ReadOnlySpan<byte> OriginBuffer => @"92536704-1f07-4856-89a4-b0b592fea01c"u8;

	[Benchmark]
	public void ToBase32String()
	{
		for (int i = 0; i < Max; ++i)
		{
			ReadOnlySpan<byte> span = OriginBuffer;
			_ = span.ToBase32String();
		}
	}

	[Benchmark]
	public void FromBase32String()
	{
		for (int i = 0; i < Max; ++i)
		{
			ReadOnlySpan<char> span = BaseStr.AsSpan();
			_ = span.FromBase32String();
		}
	}
}
