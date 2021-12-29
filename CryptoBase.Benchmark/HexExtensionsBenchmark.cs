using BenchmarkDotNet.Attributes;
using CryptoBase.DataFormatExtensions;
using System;
using System.Text;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class HexExtensionsBenchmark
{
	[Params(1)]
	public int Max { get; set; }

	private const string RawStr = @"~中文测试12！";

	private const string RawHex = @"7EE4B8ADE69687E6B58BE8AF953132EFBC81";

	[Benchmark]
	public void ToHex()
	{
		Span<byte> span = Encoding.UTF8.GetBytes(RawStr);
		for (var i = 0; i < Max; ++i)
		{
			_ = span.ToHex();
		}
	}

	[Benchmark]
	public void ToHex_NET5()
	{
		Span<byte> span = Encoding.UTF8.GetBytes(RawStr);
		for (var i = 0; i < Max; ++i)
		{
			_ = span.ToHexString().ToLower();
		}
	}

	[Benchmark]
	public void FromHex()
	{
		for (var i = 0; i < Max; ++i)
		{
			_ = RawHex.FromHex();
		}
	}

	[Benchmark]
	public void FromHex_NET5()
	{
		for (var i = 0; i < Max; ++i)
		{
			_ = Convert.FromHexString(RawHex);
		}
	}
}
