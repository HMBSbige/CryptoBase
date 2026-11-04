using CryptoBase.EllipticCurves;
using CryptoBase.Signatures.EdDsa;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;

namespace CryptoBase.Tests.Signatures.EdDsa;

public class Ed448ScalarTest
{
	private static readonly BigInteger Two446 = BigInteger.One << 446;

	private static readonly BigInteger Two448 = BigInteger.One << 448;

	private static readonly BigInteger Two912 = BigInteger.One << 912;

	// The folds at 2^448, 2^448 and 2^446 leave remainders up to 2^691, 2^470 and 2L; all-ones low limbs make their products carry.
	[Test]
	public async Task ReduceWideMatchesBigInteger()
	{
		Random random = new(1);
		List<BigInteger> values = [0, 1, L - 1, L, L + 1, 2 * L, 4 * L - 1, 4 * L, Two448 - 1, Two448, Two448 + 1, Two448 * L - 1, Two448 * L, (Two448 - 1) * L, Two912 - L, Two912 - 1];
		values.AddRange([Two446 - 1, Two446, Two446 + 1, Two446 * L - 1, Two446 * L, Two446 * L + L - 1, 2 * L - 1, 2 * L + Two446]);
		values.AddRange([(BigInteger.One << 470) - 1, BigInteger.One << 470, (BigInteger.One << 691) - 1, BigInteger.One << 691, Two912 - Two448, (Two448 - 1) * Two448, Two448 * Two448 - 1, (Two446 - 1) * (BigInteger.One << 24) + Two446 - 1]);
		values.AddRange(Enumerable.Range(0, 300).Select(_ => RandomBelow(random, Two912)));
		values.AddRange(Enumerable.Range(0, 200).Select(_ => PatternedValue(random, 15) % Two912));
		List<string> failures = [];

		foreach (BigInteger value in values)
		{
			Ed448Scalar.ReduceWide(EncodeInteger(value, Ed448Scalar.WideLength), out FieldElement<Ed448Order> result);

			if (ToValue(in result) != value % L)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The pruned secret scalar may be any 448-bit value.
	[Test]
	public async Task ToMontgomeryReducesAnyValue()
	{
		Random random = new(2);
		List<BigInteger> values = [0, 1, L - 1, L, L + 1, 3 * L, 4 * L - 1, 4 * L, Two448 - L, Two448 - 1, BigInteger.One << 447, Two448 - 4];
		values.AddRange(Enumerable.Range(0, 200).Select(_ => RandomBelow(random, Two448)));
		values.AddRange(Enumerable.Range(0, 100).Select(_ => PatternedValue(random, 7)));
		List<string> failures = [];

		foreach (BigInteger value in values)
		{
			Ed448Scalar.ToMontgomery(EncodeInteger(value), out FieldElement<Ed448Order> result);

			if (ToValue(in result) != value * Two448 % L)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// k and r are below L, as ReduceWide leaves them; s is any 448-bit value.
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
				foreach (BigInteger s in (BigInteger[])[0, 1, L - 1, L, Two448 - 1])
				{
					cases.Add((k, s, r));
				}
			}
		}

		for (int i = 0; i < 300; ++i)
		{
			cases.Add((RandomBelow(random, L), RandomBelow(random, Two448), RandomBelow(random, L)));
		}

		List<string> failures = [];

		foreach ((BigInteger k, BigInteger s, BigInteger r) in cases)
		{
			Ed448Scalar.ReduceWide(EncodeInteger(k, Ed448Scalar.WideLength), out FieldElement<Ed448Order> kElement);
			Ed448Scalar.ReduceWide(EncodeInteger(r, Ed448Scalar.WideLength), out FieldElement<Ed448Order> rElement);
			Ed448Scalar.ToMontgomery(EncodeInteger(s), out FieldElement<Ed448Order> sElement);
			Ed448Scalar.MultiplyAdd(in kElement, in sElement, in rElement, out FieldElement<Ed448Order> result);

			if (ToValue(in result) != (r + k * s) % L)
			{
				failures.Add($"k = {k:X}, s = {s:X}, r = {r:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A nonzero 57th byte is never canonical, whatever the first 56 bytes.
	[Test]
	public async Task IsCanonicalTellsValuesBelowL()
	{
		Random random = new(4);
		// Values that share the top limbs of L, 2^62 − 1, 2^64 − 1 and 2^64 − 1, reach every comparison.
		List<BigInteger> values = [0, 1, L - 1, L, L + 1, Two446 - 1, Two446, Two448 - 1, Two448, Two448 + 1, Two448 + L - 1, (BigInteger.One << 455) + 1, (BigInteger.One << 456) - 1];

		for (int shift = 64; shift < 448; shift += 64)
		{
			values.AddRange([L - (BigInteger.One << shift), L + (BigInteger.One << shift)]);
		}

		values.AddRange(Enumerable.Range(0, 100).Select(_ => RandomBelow(random, 2 * L)));
		values.AddRange(Enumerable.Range(0, 100).Select(_ => RandomBelow(random, BigInteger.One << 456)));
		List<string> failures = [];

		foreach (BigInteger value in values)
		{
			if (Ed448Scalar.IsCanonical(EncodeInteger(value, Ed448Scalar.Length)) != value < L)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The 57th byte of S is 0 whatever the destination held.
	[Test]
	public async Task WriteIsLittleEndian()
	{
		BigInteger value = L - 2;
		Ed448Scalar.ReduceWide(EncodeInteger(value, Ed448Scalar.WideLength), out FieldElement<Ed448Order> element);
		byte[] scalar = new byte[Ed448Scalar.Length - 1];
		byte[] encoded = new byte[Ed448Scalar.Length];
		encoded.AsSpan().Fill(0xFF);
		Ed448Scalar.Write(in element, scalar);
		Ed448Scalar.Write(in element, encoded);

		using (Assert.Multiple())
		{
			await Assert.That(scalar).IsEquivalentTo(EncodeInteger(value), CollectionOrdering.Matching);
			await Assert.That(encoded).IsEquivalentTo(EncodeInteger(value, Ed448Scalar.Length), CollectionOrdering.Matching);
		}
	}

	private static BigInteger ToValue(in FieldElement<Ed448Order> element)
	{
		byte[] encoded = new byte[Ed448Scalar.Length];
		Ed448Scalar.Write(in element, encoded);
		return DecodeInteger(encoded);
	}

	// Limbs of 0, 1, 2^63 and 2^64 − 1 make long carry chains.
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
