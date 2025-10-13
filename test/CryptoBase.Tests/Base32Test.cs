using CryptoBase.DataFormatExtensions;
using System.Text;

namespace CryptoBase.Tests;

public class Base32Test
{
	[Theory]
	[InlineData(@"", @"")]
	[InlineData(@"f", @"MY======")]
	[InlineData(@"fo", @"MZXQ====")]
	[InlineData(@"foo", @"MZXW6===")]
	[InlineData(@"foob", @"MZXW6YQ=")]
	[InlineData(@"fooba", @"MZXW6YTB")]
	[InlineData(@"foobar", @"MZXW6YTBOI======")]
	[InlineData(@"foobar1", @"MZXW6YTBOIYQ====")]
	[InlineData(@"foobar12", @"MZXW6YTBOIYTE===")]
	[InlineData(@"foobar123", @"MZXW6YTBOIYTEMY=")]
	[InlineData(@"123456789012345678901234567890123456789", @"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOI=")]
	[InlineData(@"1234567890123456789012345678901234567890", @"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")]
	[InlineData(@"Never did sun more beautifully steep", @"JZSXMZLSEBSGSZBAON2W4IDNN5ZGKIDCMVQXK5DJMZ2WY3DZEBZXIZLFOA======")]
	[InlineData(@"92536704-1f07-4856-89a4-b0b592fea01c", @"HEZDKMZWG4YDILJRMYYDOLJUHA2TMLJYHFQTILLCGBRDKOJSMZSWCMBRMM======")]
	[InlineData(@"！114中文测试514√", @"566ICMJRGTSLRLPGS2D6NNML5CXZKNJRGTRIRGQ=")]
	public void Test(string originExpected, string base32Expected)
	{
		ReadOnlySpan<byte> originBuffer = Encoding.UTF8.GetBytes(originExpected);

		Assert.Equal(base32Expected, originBuffer.ToBase32String());

		Span<byte> b = base32Expected.AsSpan().FromBase32String();
		Assert.True(b.SequenceEqual(originBuffer));
	}
}
