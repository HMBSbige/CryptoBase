using CryptoBase.Ciphers.Streams;
using static CryptoBase.Tests.Ciphers.Streams.SnuffleCipherTestUtils;

namespace CryptoBase.Tests.Ciphers.Streams;

public class SnuffleCipherCounterTest
{
	[Test]
	[MethodDataSource(typeof(SnuffleCipherTestUtils), nameof(CipherCases))]
	public async Task SetCounterMatchesSequentialStreamAfterPartialBlocks(SnuffleCase cipher)
	{
		using SnuffleCipher oracle = cipher.Create();
		byte[] expected = new byte[321];
		oracle.Xor(new byte[expected.Length], expected);
		byte[] source = new byte[129];
		byte[] actual = new byte[source.Length];

		foreach (int consumed in new[] { 1, 63, 64, 65 })
		{
			using SnuffleCipher crypto = cipher.Create();
			crypto.Xor(source.AsSpan().Slice(0, consumed), actual);

			foreach (ulong counter in new ulong[] { 3, 1, 1, 0 })
			{
				SetCounter(crypto, counter);
				crypto.Xor(source.AsSpan().Slice(0, 1), actual);
				crypto.Xor(source.AsSpan().Slice(1), actual.AsSpan().Slice(1));

				byte[] expectedSegment = expected.AsSpan().Slice((int)counter * 64, actual.Length).ToArray();
				await Assert.That(actual).IsEquivalentTo(expectedSegment, CollectionOrdering.Matching);
			}
		}
	}
}
