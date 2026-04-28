using CryptoBase.DataFormatExtensions;
using System.Text;

namespace CryptoBase.Tests;

public class Base32Test
{
	[Test]
	[Arguments(@"", @"")]
	[Arguments(@"f", @"MY======")]
	[Arguments(@"fo", @"MZXQ====")]
	[Arguments(@"foo", @"MZXW6===")]
	[Arguments(@"foob", @"MZXW6YQ=")]
	[Arguments(@"fooba", @"MZXW6YTB")]
	[Arguments(@"foobar", @"MZXW6YTBOI======")]
	[Arguments(@"foobar1", @"MZXW6YTBOIYQ====")]
	[Arguments(@"foobar12", @"MZXW6YTBOIYTE===")]
	[Arguments(@"foobar123", @"MZXW6YTBOIYTEMY=")]
	[Arguments(@"123456789012345678901234567890123456789", @"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOI=")]
	[Arguments(@"1234567890123456789012345678901234567890", @"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")]
	[Arguments(@"Never did sun more beautifully steep", @"JZSXMZLSEBSGSZBAON2W4IDNN5ZGKIDCMVQXK5DJMZ2WY3DZEBZXIZLFOA======")]
	[Arguments(@"92536704-1f07-4856-89a4-b0b592fea01c", @"HEZDKMZWG4YDILJRMYYDOLJUHA2TMLJYHFQTILLCGBRDKOJSMZSWCMBRMM======")]
	[Arguments(@"！114中文测试514√", @"566ICMJRGTSLRLPGS2D6NNML5CXZKNJRGTRIRGQ=")]
	public async Task Test(string originExpected, string base32Expected)
	{
		byte[] originBuffer = Encoding.UTF8.GetBytes(originExpected);

		await Assert.That(base32Expected.SequenceEqual(originBuffer.ToBase32String())).IsTrue();

		byte[] b = base32Expected.AsSpan().FromBase32String();

		await Assert.That(originBuffer.SequenceEqual(b)).IsTrue();
	}
}
