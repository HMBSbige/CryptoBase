using CryptoBase.Kdf.Argon2;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf.Argon2;

public class Argon2WipeTest
{
	private const int GuardLength = 64;

	[Test]
	[Arguments(1, 3)]
	[Arguments(3, 257)]
	public async Task DerivationWipesTheWholeMemory(int lanes, int segmentLength)
	{
		(bool wiped, bool guarded) = Derive(lanes, segmentLength);

		using (Assert.Multiple())
		{
			await Assert.That(wiped).IsTrue();
			await Assert.That(guarded).IsTrue();
		}
	}

	private static unsafe (bool Wiped, bool Guarded) Derive(int lanes, int segmentLength)
	{
		int length = lanes * segmentLength * Argon2Core.SyncPoints * Argon2Block.SizeInBytes;
		byte* region = (byte*)NativeMemory.AlignedAlloc((nuint)(GuardLength + length + GuardLength), Argon2MemoryCache.Alignment);

		try
		{
			Span<byte> buffer = new(region, GuardLength + length + GuardLength);
			PrepareDestination(buffer);
			byte[] prehash = new byte[Argon2Core.PrehashLength];
			Random.Shared.NextBytes(prehash);

			new Argon2Instance<Argon2Scalar>((Argon2Block*)(region + GuardLength), lanes, segmentLength, 2, -1, false).Derive(prehash, new byte[32]);

			bool wiped = !buffer.Slice(GuardLength, length).ContainsAnyExcept((byte)0);
			bool guarded = !buffer.Slice(0, GuardLength).ContainsAnyExcept(DestinationSentinel) && !buffer.Slice(GuardLength + length).ContainsAnyExcept(DestinationSentinel);
			return (wiped, guarded);
		}
		finally
		{
			NativeMemory.AlignedFree(region);
		}
	}
}
