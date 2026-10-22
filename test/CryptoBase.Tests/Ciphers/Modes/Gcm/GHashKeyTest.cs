using CryptoBase.Ciphers.Modes.Gcm;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes.Gcm;

public class GHashKeyTest
{
	[Test]
	public async Task DisposeErasesCachedTables()
	{
		GHashKey key = GHashKey.Create(CreateDeterministicSource(16));
		List<Func<byte[]>> tables = [];

		try
		{
			if (GHashX86.IsSupported)
			{
				tables.Add(GetReader(key.GetFourBlock()));
				tables.Add(GetReader(key.GetVector128()));
			}

			if (GHashX86.IsSupported256)
			{
				tables.Add(GetReader(key.GetVector256()));
			}

			if (GHashX86.IsSupported512)
			{
				tables.Add(GetReader(key.GetVector512()));
			}

			if (GHashArm.IsSupported)
			{
				tables.Add(GetReader(key.GetArm()));
			}

			foreach (Func<byte[]> table in tables)
			{
				await Assert.That(table()).Any(static value => value is not 0);
			}
		}
		finally
		{
			key.Dispose();
		}

		await Assert.That(key.Value.AsReadOnlySpan().ToArray()).All(static value => value is 0);

		foreach (Func<byte[]> table in tables)
		{
			await Assert.That(table()).All(static value => value is 0);
		}
	}

	private static Func<byte[]> GetReader<T>(GHashKeyTable<T> table) where T : unmanaged
	{
		return () => table.Value.AsReadOnlySpan().ToArray();
	}
}
