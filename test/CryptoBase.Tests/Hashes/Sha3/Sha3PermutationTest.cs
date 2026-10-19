using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;

namespace CryptoBase.Tests.Hashes.Sha3;

public class Sha3PermutationTest
{
	// Keccak-f[1600] applied to the all-zero state, then to its own output, from the Keccak team's
	// https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt
	internal static readonly ulong[] ZeroStatePermutedOnce =
	[
		0xF1258F7940E1DDE7UL, 0x84D5CCF933C0478AUL, 0xD598261EA65AA9EEUL, 0xBD1547306F80494DUL, 0x8B284E056253D057UL,
		0xFF97A42D7F8E6FD4UL, 0x90FEE5A0A44647C4UL, 0x8C5BDA0CD6192E76UL, 0xAD30A6F71B19059CUL, 0x30935AB7D08FFC64UL,
		0xEB5AA93F2317D635UL, 0xA9A6E6260D712103UL, 0x81A57C16DBCF555FUL, 0x43B831CD0347C826UL, 0x01F22F1A11A5569FUL,
		0x05E5635A21D9AE61UL, 0x64BEFEF28CC970F2UL, 0x613670957BC46611UL, 0xB87C5A554FD00ECBUL, 0x8C3EE88A1CCF32C8UL,
		0x940C7922AE3A2614UL, 0x1841F924A2C509E4UL, 0x16F53526E70465C2UL, 0x75F644E97F30A13BUL, 0xEAF1FF7B5CECA249UL
	];

	internal static readonly ulong[] ZeroStatePermutedTwice =
	[
		0x2D5C954DF96ECB3CUL, 0x6A332CD07057B56DUL, 0x093D8D1270D76B6CUL, 0x8A20D9B25569D094UL, 0x4F9C4F99E5E7F156UL,
		0xF957B9A2DA65FB38UL, 0x85773DAE1275AF0DUL, 0xFAF4F247C3D810F7UL, 0x1F1B9EE6F79A8759UL, 0xE4FECC0FEE98B425UL,
		0x68CE61B6B9CE68A1UL, 0xDEEA66C4BA8F974FUL, 0x33C43D836EAFB1F5UL, 0xE00654042719DBD9UL, 0x7CF8A9F009831265UL,
		0xFD5449A6BF174743UL, 0x97DDAD33D8994B40UL, 0x48EAD5FC5D0BE774UL, 0xE3B8C8EE55B7B03CUL, 0x91A0226E649E42E9UL,
		0x900E3129E7BADD7BUL, 0x202A9EC5FAA3CCE8UL, 0x5B3402464E1C3DB6UL, 0x609F4E62A44C1059UL, 0x20D06CD26A8FBF5CUL
	];

	[Test]
	public async Task PermuteMatchesKeccakTeamValues()
	{
		InlineArray25<ulong> state = default;

		KeccakP1600.Permute(ref state);
		await Assert.That(ToArray(state)).IsEquivalentTo(ZeroStatePermutedOnce, CollectionOrdering.Matching);

		KeccakP1600.Permute(ref state);
		await Assert.That(ToArray(state)).IsEquivalentTo(ZeroStatePermutedTwice, CollectionOrdering.Matching);
	}

	[Test]
	public async Task ReferenceMatchesKeccakTeamValues()
	{
		ulong[] state = new ulong[25];

		KeccakReference.Permute(state);
		await Assert.That(state).IsEquivalentTo(ZeroStatePermutedOnce, CollectionOrdering.Matching);

		KeccakReference.Permute(state);
		await Assert.That(state).IsEquivalentTo(ZeroStatePermutedTwice, CollectionOrdering.Matching);
	}

	// Random states checked against the reference cover PermuteScalar too, even where Permute takes the AVX-512 path.
	[Test]
	[Arguments(1)]
	[Arguments(2)]
	[Arguments(3)]
	public async Task PermuteMatchesReference(int seed)
	{
		Random random = new(seed);
		ulong[] expected = new ulong[25];

		for (int i = 0; i < expected.Length; ++i)
		{
			expected[i] = (ulong)random.NextInt64(long.MinValue, long.MaxValue);
		}

		InlineArray25<ulong> state = default;
		InlineArray25<ulong> scalarState = default;
		expected.CopyTo(state);
		expected.CopyTo(scalarState);

		for (int i = 0; i < 4; ++i)
		{
			KeccakReference.Permute(expected);
			KeccakP1600.Permute(ref state);
			KeccakP1600.PermuteScalar(ref scalarState);

			using (Assert.Multiple())
			{
				await Assert.That(ToArray(state)).IsEquivalentTo(expected, CollectionOrdering.Matching);
				await Assert.That(ToArray(scalarState)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}
		}
	}

	private static ulong[] ToArray(in InlineArray25<ulong> state)
	{
		return ((ReadOnlySpan<ulong>)state).ToArray();
	}
}
