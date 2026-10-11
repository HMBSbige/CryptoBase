using CryptoBase.Kdf.Argon2;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.Kdf.Argon2;

public class Argon2KernelTest
{
	[Test]
	public async Task EveryKernelIsListed()
	{
		Type[] implemented = typeof(IArgon2Kernel).Assembly.GetTypes().Where(static type => type is { IsInterface: false, IsAbstract: false } && type.IsAssignableTo(typeof(IArgon2Kernel))).ToArray();

		await Assert.That(Argon2KernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(implemented);
	}

	[Test]
	[MethodDataSource(typeof(Argon2KernelCase), nameof(Argon2KernelCase.All))]
	public async Task MatchesReference(Argon2KernelCase kernel)
	{
		if (!kernel.IsSupported)
		{
			Skip.Test($"{kernel} is not supported here.");
		}

		Random random = new(0x1234_5678);

		foreach (bool xorDestination in new[] { false, true })
		{
			for (int iteration = 0; iteration < 16; ++iteration)
			{
				ulong[] previousWords = CreateWords(random);
				ulong[] referenceWords = CreateWords(random);
				ulong[] destinationWords = CreateWords(random);
				ulong[] expected = Argon2Reference.G(previousWords, referenceWords);

				if (xorDestination)
				{
					for (int i = 0; i < expected.Length; ++i)
					{
						expected[i] ^= destinationWords[i];
					}
				}

				Argon2Block previous = ToBlock(previousWords);
				Argon2Block reference = ToBlock(referenceWords);
				Argon2Block destination = ToBlock(destinationWords);
				Argon2Block scratch = default;
				kernel.Compress(ref previous, ref reference, ref destination, ref scratch, xorDestination);

				using (Assert.Multiple())
				{
					await Assert.That(ToWords(destination)).IsEquivalentTo(expected, CollectionOrdering.Matching);
					await Assert.That(ToWords(previous)).IsEquivalentTo(previousWords, CollectionOrdering.Matching);
					await Assert.That(ToWords(reference)).IsEquivalentTo(referenceWords, CollectionOrdering.Matching);
				}
			}
		}
	}

	private static ulong[] CreateWords(Random random)
	{
		ulong[] words = new ulong[Argon2Reference.BlockWords];
		random.NextBytes(MemoryMarshal.AsBytes(words.AsSpan()));
		return words;
	}

	private static Argon2Block ToBlock(ulong[] words)
	{
		Argon2Block block = default;
		words.CopyTo(block);
		return block;
	}

	private static ulong[] ToWords(Argon2Block block)
	{
		return ((ReadOnlySpan<ulong>)block).ToArray();
	}
}
