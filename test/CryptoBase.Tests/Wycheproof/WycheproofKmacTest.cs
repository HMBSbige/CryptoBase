using CryptoBase.Macs.Kmac;

namespace CryptoBase.Tests.Wycheproof;

// The tag size of each group is the output length L, 128, 256 or 512 bits; the invalid vectors modify the tag.
public class WycheproofKmacTest
{
	[Test]
	[WycheproofVectors<KmacTestGroup, KmacTestVector>("kmac128_no_customization_test.json")]
	public async Task Kmac128NoCustomization(KmacTestVector vector)
	{
		byte[] mac = new byte[vector.TagSize / 8];
		Kmac128Algorithm.Mac(vector.Key, vector.Msg, mac);

		using Kmac128Algorithm kmac = Kmac128Algorithm.Create(vector.Key);
		kmac.Append(vector.Msg);
		byte[] incrementalMac = new byte[mac.Length];
		kmac.GetMacAndReset(incrementalMac);

		await Verify(vector, mac, incrementalMac);
	}

	[Test]
	[WycheproofVectors<KmacTestGroup, KmacTestVector>("kmac256_no_customization_test.json")]
	public async Task Kmac256NoCustomization(KmacTestVector vector)
	{
		byte[] mac = new byte[vector.TagSize / 8];
		Kmac256Algorithm.Mac(vector.Key, vector.Msg, mac);

		using Kmac256Algorithm kmac = Kmac256Algorithm.Create(vector.Key);
		kmac.Append(vector.Msg);
		byte[] incrementalMac = new byte[mac.Length];
		kmac.GetMacAndReset(incrementalMac);

		await Verify(vector, mac, incrementalMac);
	}

	private static async Task Verify(KmacTestVector vector, byte[] mac, byte[] incrementalMac)
	{
		using (Assert.Multiple())
		{
			await Assert.That(vector.Tag.Length).IsEqualTo(mac.Length);
			await Assert.That(incrementalMac).IsEquivalentTo(mac, CollectionOrdering.Matching);
			await Assert.That(mac.AsSpan().SequenceEqual(vector.Tag)).IsEqualTo(vector.Result is WycheproofResult.Valid);
		}
	}
}
