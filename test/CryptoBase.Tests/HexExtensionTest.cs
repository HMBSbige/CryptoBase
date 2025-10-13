using CryptoBase.DataFormatExtensions;
using System.Security.Cryptography;
using System.Text;

namespace CryptoBase.Tests;

public class HexExtensionTest
{
	[Theory]
	[InlineData(@"0123456789ABCDEFFEDCBA9876543210", @"3031323334353637383941424344454646454443424139383736353433323130")]
	[InlineData(@"~中文测试12！", @"7ee4b8ade69687e6b58be8af953132efbc81")]
	public void ToHexTest(string input, string expected)
	{
		Span<byte> span = Encoding.UTF8.GetBytes(input);
		Assert.Equal(expected, span.ToHex());
	}

	[Theory]
	[InlineData(@"3031323334353637383941424344454646454443424139383736353433323130", @"0123456789ABCDEFFEDCBA9876543210")]
	[InlineData(@"7ee4b8ade69687e6b58be8af953132efbc81", @"~中文测试12！")]
	[InlineData(@"31313435313431393139383130", @"1145141919810")]
	[InlineData(@"7EE4B8ADE69687E6B58BE8AF953132EFBC81", @"~中文测试12！")]
	public void FromHexTest(string input, string expected)
	{
		Span<byte> span = Encoding.UTF8.GetBytes(expected);
		Assert.True(span.SequenceEqual(input.FromHex()));
	}

	[Fact]
	public void LargeInputTest()
	{
		byte[] expected = RandomNumberGenerator.GetBytes(10 * 1024 * 1024);
		string hex = expected.AsSpan().ToHex();
		Span<byte> actual = hex.FromHex();
		Assert.True(actual.SequenceEqual(expected));
	}
}
