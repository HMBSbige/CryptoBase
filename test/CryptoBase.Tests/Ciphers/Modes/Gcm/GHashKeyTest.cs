using CryptoBase.Ciphers.Modes.Gcm;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes.Gcm;

public class GHashKeyTest
{
	[Test]
	public async Task DisposeErasesCachedTables()
	{
		GHashKey key = GHashKey.Create(CreateDeterministicSource(16));
		GHashKeyTable<GHashFourBlockPrecomputedKey>? fourBlock = null;
		GHashKeyTable<GHashVector128PrecomputedKey>? vector128 = null;
		GHashKeyTable<GHashVector256PrecomputedKey>? vector256 = null;
		GHashKeyTable<GHashVector512PrecomputedKey>? vector512 = null;
		List<byte[]> before = [];

		try
		{
			if (GHashX86.IsSupported)
			{
				fourBlock = key.GetFourBlock();
				vector128 = key.GetVector128();
				before.Add(GetBytes(fourBlock));
				before.Add(GetBytes(vector128));
			}

			if (GHashX86.IsSupported256)
			{
				vector256 = key.GetVector256();
				before.Add(GetBytes(vector256));
			}

			if (GHashX86.IsSupported512)
			{
				vector512 = key.GetVector512();
				before.Add(GetBytes(vector512));
			}
		}
		finally
		{
			key.Dispose();
		}

		List<byte[]> after = [key.Value.AsReadOnlySpan().ToArray()];

		if (fourBlock is not null)
		{
			after.Add(GetBytes(fourBlock));
		}

		if (vector128 is not null)
		{
			after.Add(GetBytes(vector128));
		}

		if (vector256 is not null)
		{
			after.Add(GetBytes(vector256));
		}

		if (vector512 is not null)
		{
			after.Add(GetBytes(vector512));
		}

		foreach (byte[] bytes in before)
		{
			await Assert.That(bytes).Any(static value => value is not 0);
		}

		foreach (byte[] bytes in after)
		{
			await Assert.That(bytes).All(static value => value is 0);
		}
	}

	private static byte[] GetBytes<T>(GHashKeyTable<T> table) where T : unmanaged
	{
		return table.Value.AsReadOnlySpan().ToArray();
	}
}
