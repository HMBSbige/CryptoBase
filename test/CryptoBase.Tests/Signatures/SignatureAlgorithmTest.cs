using CryptoBase.Abstractions.Signatures;

namespace CryptoBase.Tests.Signatures;

public class SignatureAlgorithmTest
{
	[Test]
	public async Task EveryMemberHasItsOwnValue()
	{
		await Assert.That(Enum.GetValues<SignatureAlgorithm>().Distinct().Count()).IsEqualTo(Enum.GetNames<SignatureAlgorithm>().Length);
	}
}
