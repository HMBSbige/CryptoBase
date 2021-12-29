using BenchmarkDotNet.Attributes;
using CryptoBase.DataFormatExtensions;
using System;
using System.Linq;
using System.Text;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class Base32Benchmark
{
	[Params(1)]
	public int Max { get; set; }

	private const string BaseStr = @"HEZDKMZWG4YDILJRMYYDOLJUHA2TMLJYHFQTILLCGBRDKOJSMZSWCMBRMM======";

	private readonly byte[] _originBuffer = Encoding.UTF8.GetBytes(@"92536704-1f07-4856-89a4-b0b592fea01c").ToArray();

	[Benchmark]
	public void ToBase32String()
	{
		for (var i = 0; i < Max; ++i)
		{
			ReadOnlySpan<byte> span = _originBuffer;
			_ = span.ToBase32String();
		}
	}

	[Benchmark]
	public void FromBase32String()
	{
		for (var i = 0; i < Max; ++i)
		{
			var span = BaseStr.AsSpan();
			_ = span.FromBase32String();
		}
	}
}
