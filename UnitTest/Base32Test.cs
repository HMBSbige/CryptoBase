using CryptoBase.DataFormatExtensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace UnitTest
{
	[TestClass]
	public class Base32Test
	{
		[TestMethod]
		[DataRow(@"", @"")]
		[DataRow(@"f", @"MY======")]
		[DataRow(@"fo", @"MZXQ====")]
		[DataRow(@"foo", @"MZXW6===")]
		[DataRow(@"foob", @"MZXW6YQ=")]
		[DataRow(@"fooba", @"MZXW6YTB")]
		[DataRow(@"foobar", @"MZXW6YTBOI======")]
		[DataRow(@"foobar1", @"MZXW6YTBOIYQ====")]
		[DataRow(@"foobar12", @"MZXW6YTBOIYTE===")]
		[DataRow(@"foobar123", @"MZXW6YTBOIYTEMY=")]
		[DataRow(@"123456789012345678901234567890123456789", @"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOI=")]
		[DataRow(@"1234567890123456789012345678901234567890", @"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")]
		[DataRow(@"Never did sun more beautifully steep", @"JZSXMZLSEBSGSZBAON2W4IDNN5ZGKIDCMVQXK5DJMZ2WY3DZEBZXIZLFOA======")]
		[DataRow(@"92536704-1f07-4856-89a4-b0b592fea01c", @"HEZDKMZWG4YDILJRMYYDOLJUHA2TMLJYHFQTILLCGBRDKOJSMZSWCMBRMM======")]
		[DataRow(@"！114中文测试514√", @"566ICMJRGTSLRLPGS2D6NNML5CXZKNJRGTRIRGQ=")]
		public void Test(string originExpected, string base32Expected)
		{
			ReadOnlySpan<byte> originBuffer = Encoding.UTF8.GetBytes(originExpected);

			Assert.AreEqual(base32Expected, originBuffer.ToBase32String());

			Span<byte> b = base32Expected.AsSpan().FromBase32String();
			Assert.IsTrue(b.SequenceEqual(originBuffer));
		}
	}
}
