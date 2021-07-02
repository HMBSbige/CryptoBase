using CryptoBase;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace UnitTest
{
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
		[DataRow(@"30-31-32-33-34-35-36-37-38-39-41-42-43-44-45-46-46-45-44-43-42-41-39-38-37-36-35-34-33-32-31-30", @"0123456789ABCDEFFEDCBA9876543210")]
		[DataRow(@"0x7e0xe40xb80xad0xe60x960x870xe60xb50x8b0xe80xaf0x950x310x320xef0xbc0x81", @"~中文测试12！")]
		[DataRow(@"31313435313431393139383130", @"1145141919810")]
		[DataRow(@"7EE4B8ADE69687E6B58BE8AF953132EFBC81", @"~中文测试12！")]
		public void FromHexTest(string input, string expected)
		{
			Span<byte> span = Encoding.UTF8.GetBytes(expected);
			Assert.IsTrue(span.SequenceEqual(input.FromHex()));
		}
	}
}
