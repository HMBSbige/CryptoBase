using CryptoBase.EllipticCurves;
using CryptoBase.Signatures.EdDsa;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;

namespace CryptoBase.Tests.Signatures.EdDsa;

// The arithmetic modulo L of signing and verification against BigInteger, at the edges of each input range and at random.
public class Ed25519ScalarTest
{
	private static readonly BigInteger Two256 = BigInteger.One << 256;

	private static readonly BigInteger Two512 = BigInteger.One << 512;

	[Test]
	public async Task ReduceWideMatchesBigInteger()
	{
		Random random = new(1);
		List<BigInteger> values = [0, 1, L - 1, L, L + 1, 2 * L, Two256 - 1, Two256, Two256 + 1, Two256 * L - 1, Two256 * L, (Two256 - 1) * L, Two512 - L, Two512 - 1];
		values.AddRange(Enumerable.Range(0, 200).Select(_ => RandomBelow(random, Two512)));
		values.AddRange(Enumerable.Range(0, 100).Select(_ => PatternedValue(random, 8)));
		List<string> failures = [];

		foreach (BigInteger value in values)
		{
			Ed25519Scalar.ReduceWide(EncodeInteger(value, Ed25519Scalar.WideLength), out FieldElement<Ed25519Order> result);

			if (ToValue(in result) != value % L)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The Montgomery form of any 256-bit value, as the pruned secret scalar is, is that of the value mod L.
	[Test]
	public async Task ToMontgomeryReducesAnyValue()
	{
		Random random = new(2);
		List<BigInteger> values = [0, 1, L - 1, L, L + 1, 15 * L, Two256 - L, Two256 - 1, (BigInteger.One << 254) + 8, (BigInteger.One << 255) - 8];
		values.AddRange(Enumerable.Range(0, 200).Select(_ => RandomBelow(random, Two256)));
		values.AddRange(Enumerable.Range(0, 100).Select(_ => PatternedValue(random, 4)));
		List<string> failures = [];

		foreach (BigInteger value in values)
		{
			Ed25519Scalar.ToMontgomery(EncodeInteger(value), out FieldElement<Ed25519Order> result);

			if (ToValue(in result) != value * Two256 % L)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// k and r are below L, as ReduceWide leaves them; s is any 256-bit value.
	[Test]
	public async Task MultiplyAddMatchesBigInteger()
	{
		Random random = new(3);
		BigInteger[] edges = [0, 1, L - 1];
		List<(BigInteger K, BigInteger S, BigInteger R)> cases = [];

		foreach (BigInteger k in edges)
		{
			foreach (BigInteger r in edges)
			{
				foreach (BigInteger s in (BigInteger[])[0, 1, L - 1, L, Two256 - 1])
				{
					cases.Add((k, s, r));
				}
			}
		}

		for (int i = 0; i < 300; ++i)
		{
			cases.Add((RandomBelow(random, L), RandomBelow(random, Two256), RandomBelow(random, L)));
		}

		List<string> failures = [];

		foreach ((BigInteger k, BigInteger s, BigInteger r) in cases)
		{
			Ed25519Scalar.ReduceWide(EncodeInteger(k, Ed25519Scalar.WideLength), out FieldElement<Ed25519Order> kElement);
			Ed25519Scalar.ReduceWide(EncodeInteger(r, Ed25519Scalar.WideLength), out FieldElement<Ed25519Order> rElement);
			Ed25519Scalar.ToMontgomery(EncodeInteger(s), out FieldElement<Ed25519Order> sElement);
			Ed25519Scalar.MultiplyAdd(in kElement, in sElement, in rElement, out FieldElement<Ed25519Order> result);

			if (ToValue(in result) != (r + k * s) % L)
			{
				failures.Add($"k = {k:X}, s = {s:X}, r = {r:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task IsCanonicalTellsValuesBelowL()
	{
		Random random = new(4);
		// The limbs of L are, from the top, 2^60, 0, 0x14DEF9DEA2F79CD6 and 0x5812631A5CF5D3ED, so values that share the top limbs of L reach every comparison.
		List<BigInteger> values = [0, 1, L - 1, L, L + 1, L - (BigInteger.One << 64), L + (BigInteger.One << 64), L - (BigInteger.One << 128), L + (BigInteger.One << 128), (BigInteger.One << 252) - 1, BigInteger.One << 252, Two256 - 1];
		values.AddRange(Enumerable.Range(0, 100).Select(_ => RandomBelow(random, 2 * L)));
		List<string> failures = [];

		foreach (BigInteger value in values)
		{
			if (Ed25519Scalar.IsCanonical(EncodeInteger(value)) != value < L)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task WriteIsLittleEndian()
	{
		BigInteger value = L - 2;
		Ed25519Scalar.ReduceWide(EncodeInteger(value, Ed25519Scalar.WideLength), out FieldElement<Ed25519Order> element);
		byte[] encoded = new byte[Ed25519Scalar.Length];
		Ed25519Scalar.Write(in element, encoded);

		await Assert.That(encoded).IsEquivalentTo(EncodeInteger(value), CollectionOrdering.Matching);
	}

	private static BigInteger ToValue(in FieldElement<Ed25519Order> element)
	{
		byte[] encoded = new byte[Ed25519Scalar.Length];
		Ed25519Scalar.Write(in element, encoded);
		return DecodeInteger(encoded);
	}

	// Limbs of 0, 1, 2^63, 2^64 − 1 or a random value, which make long carry chains.
	private static BigInteger PatternedValue(Random random, int limbCount)
	{
		ulong[] patterns = [0, 1, 1UL << 63, ulong.MaxValue];
		BigInteger value = 0;

		for (int i = 0; i < limbCount; ++i)
		{
			int pattern = random.Next(patterns.Length + 1);
			ulong limb = pattern < patterns.Length ? patterns[pattern] : (ulong)random.NextInt64() ^ (ulong)random.Next() << 63;
			value = value << 64 | limb;
		}

		return value;
	}
}
