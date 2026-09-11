using CryptoBase.Abstractions.Macs;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Macs;

internal static class MacAlgorithmTestUtils
{
	internal static Task VerifyVector<TMac>(string keyHex, string sourceHex, string expectedHex) where TMac : IOneShotMacAlgorithm
	{
		return VerifyVector<TMac>(Convert.FromHexString(keyHex), Convert.FromHexString(sourceHex), Convert.FromHexString(expectedHex));
	}

	internal static async Task VerifyVector<TMac>(byte[] key, byte[] source, byte[] expected) where TMac : IOneShotMacAlgorithm
	{
		byte[] keyCopy = (byte[])key.Clone();
		byte[] sourceCopy = (byte[])source.Clone();
		byte[] destination = new byte[TMac.MacLengthInBytes + 1];

		await Assert.That(TMac.MacLengthInBytes).IsEqualTo(expected.Length);

		PrepareDestination(destination);
		int written = TMac.Mac(key, source, destination);
		await AssertOutput(destination, expected, written);
		await Assert.That(key).IsEquivalentTo(keyCopy, CollectionOrdering.Matching);
		await Assert.That(source).IsEquivalentTo(sourceCopy, CollectionOrdering.Matching);
	}
}
