using CryptoBase.Internal;

namespace CryptoBase.Tests;

public class SystemRandomTest
{
	[Test]
	public async Task UsesGetRandomOnLinux()
	{
		await Assert.That(SystemRandom.UsesGetRandom).IsEqualTo(OperatingSystem.IsLinux()).Because("Linux CI must exercise getrandom rather than silently fall back");
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(32)]
	[Arguments(257)]
	[Arguments(1024 * 1024)]
	public async Task FillProducesRandomBytes(int length)
	{
		byte[] first = new byte[length];
		byte[] second = new byte[length];

		SystemRandom.Fill(first);
		SystemRandom.Fill(second);

		if (length < 32)
		{
			return;
		}

		// A zero 32-byte block happens with probability 2^-256, so one means the buffer was left unfilled.
		List<string> zeroBlocks = [];

		for (int offset = 0; offset + 32 <= length; offset += 32)
		{
			if (!first.AsSpan(offset, 32).ContainsAnyExcept((byte)0))
			{
				zeroBlocks.Add($"first at {offset}");
			}

			if (!second.AsSpan(offset, 32).ContainsAnyExcept((byte)0))
			{
				zeroBlocks.Add($"second at {offset}");
			}
		}

		await Assert.That(zeroBlocks).IsEmpty();
		await Assert.That(first.AsSpan().SequenceEqual(second)).IsFalse();
	}
}
