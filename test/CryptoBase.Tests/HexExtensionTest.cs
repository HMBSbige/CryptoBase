using CryptoBase.DataFormatExtensions;
using System.Security.Cryptography;
using System.Text;

namespace CryptoBase.Tests;

public class HexExtensionTest
{
	[Test]
	[Arguments(@"0123456789ABCDEFFEDCBA9876543210", @"3031323334353637383941424344454646454443424139383736353433323130")]
	[Arguments(@"~中文测试12！", @"7ee4b8ade69687e6b58be8af953132efbc81")]
	public async Task ToHexTest(string input, string expected)
	{
		byte[] span = Encoding.UTF8.GetBytes(input);

		await Assert.That(expected.SequenceEqual(span.ToHex())).IsTrue();
		await Assert.That(expected.ToUpperInvariant().SequenceEqual(span.ToHexString())).IsTrue();
	}

	[Test]
	[Arguments(@"3031323334353637383941424344454646454443424139383736353433323130", @"0123456789ABCDEFFEDCBA9876543210")]
	[Arguments(@"7ee4b8ade69687e6b58be8af953132efbc81", @"~中文测试12！")]
	[Arguments(@"31313435313431393139383130", @"1145141919810")]
	[Arguments(@"7EE4B8ADE69687E6B58BE8AF953132EFBC81", @"~中文测试12！")]
	public async Task FromHexTest(string input, string expected)
	{
		byte[] span = Encoding.UTF8.GetBytes(expected);

		await Assert.That(((ReadOnlySpan<byte>)span).SequenceEqual(input.FromHex())).IsTrue();
		await Assert.That(((ReadOnlySpan<byte>)span).SequenceEqual(input.AsSpan().FromHex())).IsTrue();
	}

	[Test]
	public async Task LargeInputTest()
	{
		byte[] expected = RandomNumberGenerator.GetBytes(10 * 1024 * 1024);
		await Assert.That(expected.SequenceEqual(expected.AsSpan().ToHex().FromHex())).IsTrue();
		await Assert.That(expected.SequenceEqual(expected.AsSpan().ToHex().AsSpan().FromHex())).IsTrue();
		await Assert.That(expected.SequenceEqual(expected.AsSpan().ToHexString().FromHex())).IsTrue();
		await Assert.That(expected.SequenceEqual(expected.AsSpan().ToHexString().AsSpan().FromHex())).IsTrue();
	}
}
