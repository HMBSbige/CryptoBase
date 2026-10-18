using CryptoBase.Kdf;
using System.Text;

namespace CryptoBase.Tests.Kdf.Argon2;

[InheritsTests]
public class Argon2iTest() : Argon2DeriveKeyTest(Argon2Type.Argon2i)
{
	protected override void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, Argon2Parameters parameters, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, int maxDegreeOfParallelism)
	{
		Argon2i.DeriveKey(password, salt, destination, parameters, secret, associatedData, maxDegreeOfParallelism);
	}

	// https://www.rfc-editor.org/rfc/rfc9106#section-5.2
	[Test]
	public async Task Rfc9106Vector()
	{
		byte[] tag = new byte[32];
		Argon2i.DeriveKey(Fill(32, 0x01), Fill(16, 0x02), tag, new Argon2Parameters(memorySizeInKibibytes: 32, iterations: 3, parallelism: 4), Fill(8, 0x03), Fill(12, 0x04));

		await Assert.That(tag).IsEquivalentTo(Convert.FromHexString(@"c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"), CollectionOrdering.Matching);
	}

	// The version 0x13 hashtest vectors of https://github.com/P-H-C/phc-winner-argon2/blob/f57e61e19229e23c4445b85494dbf7c07de721cb/src/test.c, except those using 256 MiB or more,
	// and the example of https://github.com/P-H-C/phc-winner-argon2/blob/f57e61e19229e23c4445b85494dbf7c07de721cb/README.md, with four lanes and a 24-byte tag.
	[Test]
	[Arguments("password", "somesalt", 2, 16, 1, @"c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0")]
	[Arguments("password", "somesalt", 2, 8, 1, @"89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f")]
	[Arguments("password", "somesalt", 2, 8, 2, @"4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61")]
	[Arguments("password", "somesalt", 1, 16, 1, @"d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf")]
	[Arguments("password", "somesalt", 4, 16, 1, @"aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b")]
	[Arguments("differentpassword", "somesalt", 2, 16, 1, @"14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee")]
	[Arguments("password", "diffsalt", 2, 16, 1, @"b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271")]
	[Arguments("password", "somesalt", 2, 16, 4, @"45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6")]
	public async Task ReferenceImplementationVector(string password, string salt, int iterations, int memoryExponent, int parallelism, string tagHex)
	{
		byte[] expected = Convert.FromHexString(tagHex);
		byte[] tag = new byte[expected.Length];
		Argon2i.DeriveKey(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), tag, new Argon2Parameters(1 << memoryExponent, iterations, parallelism));

		await Assert.That(tag).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
