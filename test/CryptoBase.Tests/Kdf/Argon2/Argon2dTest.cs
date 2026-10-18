using CryptoBase.Kdf;

namespace CryptoBase.Tests.Kdf.Argon2;

[InheritsTests]
public class Argon2dTest() : Argon2DeriveKeyTest(Argon2Type.Argon2d)
{
	protected override void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, Argon2Parameters parameters, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, int maxDegreeOfParallelism)
	{
		Argon2d.DeriveKey(password, salt, destination, parameters, secret, associatedData, maxDegreeOfParallelism);
	}

	// https://www.rfc-editor.org/rfc/rfc9106#section-5.1
	[Test]
	public async Task Rfc9106Vector()
	{
		byte[] tag = new byte[32];
		Argon2d.DeriveKey(Fill(32, 0x01), Fill(16, 0x02), tag, new Argon2Parameters(memorySizeInKibibytes: 32, iterations: 3, parallelism: 4), Fill(8, 0x03), Fill(12, 0x04));

		await Assert.That(tag).IsEquivalentTo(Convert.FromHexString(@"512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"), CollectionOrdering.Matching);
	}
}
