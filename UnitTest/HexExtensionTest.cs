using CryptoBase.DataFormatExtensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;

namespace UnitTest;

[TestClass]
public class HexExtensionTest
{
	[TestMethod]
	[DataRow(@"0123456789ABCDEFFEDCBA9876543210", @"3031323334353637383941424344454646454443424139383736353433323130")]
	[DataRow(@"~中文测试12！", @"7ee4b8ade69687e6b58be8af953132efbc81")]
	public void ToHexTest(string input, string expected)
	{
		Span<byte> span = Encoding.UTF8.GetBytes(input);
		Assert.AreEqual(expected, span.ToHex());
	}

	[TestMethod]
	[DataRow(@"3031323334353637383941424344454646454443424139383736353433323130", @"0123456789ABCDEFFEDCBA9876543210")]
	[DataRow(@"7ee4b8ade69687e6b58be8af953132efbc81", @"~中文测试12！")]
	[DataRow(@"31313435313431393139383130", @"1145141919810")]
	[DataRow(@"7EE4B8ADE69687E6B58BE8AF953132EFBC81", @"~中文测试12！")]
	public void FromHexTest(string input, string expected)
	{
		Span<byte> span = Encoding.UTF8.GetBytes(expected);
		Assert.IsTrue(span.SequenceEqual(input.FromHex()));
	}

	[TestMethod]
	public void LargeInputTest()
	{
		byte[] expected = RandomNumberGenerator.GetBytes(10 * 1024 * 1024);
		string hex = expected.AsSpan().ToHex();
		Span<byte> actual = hex.FromHex();
		Assert.IsTrue(actual.SequenceEqual(expected));
	}
}
