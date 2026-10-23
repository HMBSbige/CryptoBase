using CryptoBase.EllipticCurves;
using CryptoBase.Tests.Wycheproof;
using System.Numerics;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class MontgomeryModulusTest
{
	[Test]
	public async Task EveryModulusIsListed()
	{
		await Assert.That(ModulusCase.All().Select(static modulus => modulus.ModulusType)).IsEquivalentTo(ImplementationsOf(typeof(IMontgomeryModulus)));
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task ModulusIsTheCurveConstant(ModulusCase modulus)
	{
		EcCurveTestVector curve = WycheproofVectors.Load<EcCurveTestVector>("ec_prime_order_curves_test.json").Single(curve => curve.Name == modulus.Curve);

		await Assert.That(modulus.Modulus).IsEqualTo(ModulusCase.Decode(modulus.IsOrder ? curve.N : curve.P));
	}

	// FieldElement relies on the limb count, the encoding length and the storage following from the bit length.
	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task SizesFollowTheBitLength(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;

		using (Assert.Multiple())
		{
			await Assert.That(modulus.BitLength).IsEqualTo((int)m.GetBitLength());
			await Assert.That(modulus.LimbCount).IsEqualTo((modulus.BitLength + 63) / 64);
			await Assert.That(modulus.ByteLength).IsEqualTo((modulus.BitLength + 7) / 8);
			await Assert.That(modulus.ModulusLimbs.Length).IsEqualTo(modulus.LimbCount);
			await Assert.That(modulus.MontgomeryOneLimbs.Length).IsEqualTo(modulus.LimbCount);
			await Assert.That(modulus.RSquaredLimbs.Length).IsEqualTo(modulus.LimbCount);
			await Assert.That(modulus.StorageSize).IsEqualTo(modulus.LimbCount * sizeof(ulong));
			await Assert.That(modulus.ElementSize).IsEqualTo(modulus.LimbCount * sizeof(ulong));
		}
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task MontgomeryConstantsMatchTheModulus(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger word = BigInteger.One << 64;
		// The odd residues modulo 2^64 form a group of order 2^63.
		BigInteger inverse = BigInteger.ModPow(m, (BigInteger.One << 63) - 1, word);

		using (Assert.Multiple())
		{
			await Assert.That(m * inverse % word).IsEqualTo(BigInteger.One);
			await Assert.That((BigInteger)modulus.NegativeInverse).IsEqualTo(word - inverse);
			await Assert.That(ModulusCase.FromLimbs(modulus.MontgomeryOneLimbs)).IsEqualTo(modulus.R % m);
			await Assert.That(ModulusCase.FromLimbs(modulus.RSquaredLimbs)).IsEqualTo(modulus.R * modulus.R % m);
		}
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task InversionChainRaisesToTheModulusLessTwo(ModulusCase modulus)
	{
		byte[] chain = modulus.InversionChain;
		await Assert.That(chain.Length % 2).IsEqualTo(1);

		int stored = chain[0];
		int steps = chain.Length / 2;
		List<BigInteger> table = [1];
		BigInteger power = 1;

		for (int step = 0; step < steps; ++step)
		{
			int entry = chain[2 * step + 2];
			await Assert.That(entry).IsLessThan(table.Count);
			power = (power << chain[2 * step + 1]) + table[entry];

			if (step < stored)
			{
				table.Add(power);
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(stored).IsLessThanOrEqualTo(steps);
			await Assert.That(power).IsEqualTo(modulus.Modulus - 2);
		}
	}

	// Reduce may give any value below 2m congruent to t·R⁻¹ modulo m, for any t below m·R. The generic reduction takes u·R − Q·m to u for
	// any Q below R, so u next to m and 2m reach the extremes of its final subtraction. Patterned limbs make long carry and borrow chains.
	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task ReduceGivesTRInverseBelowTwiceTheModulus(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger r = modulus.R;
		BigInteger limit = m * r;
		BigInteger rInverse = BigInteger.ModPow(r, m - 2, m);
		Random random = new(1);
		SortedSet<BigInteger> products = [0, 1, r - 1, r, (m - 1) * (m - 1), (m - 1) * (r - 1), limit - m, limit - 1];
		BigInteger quotient = RandomBelow(random, r);

		foreach (BigInteger u in (BigInteger[])[0, 1, m - 1, m, m + 1, 2 * m - 2, 2 * m - 1])
		{
			// The least Q that keeps u·R − Q·m below m·R.
			BigInteger least = u < m ? 0 : (u - m) * r / m + 1;
			products.UnionWith([u * r, u * r - m, u * r - least * m, u * r - (least + 1) * m, u * r - quotient * m, u * r - (r - 2) * m, u * r - (r - 1) * m]);
		}

		// P-521 reduces t = h·R + a·2^55 + b through v = a + b·2^466: h next to m and the lower half next to R and 2^521 put v just below
		// 2^521, at it and at its most.
		BigInteger power = BigInteger.One << modulus.BitLength;

		foreach (BigInteger high in (BigInteger[])[0, 1, m - 2, m - 1])
		{
			foreach (BigInteger low in (BigInteger[])[0, 1, power - 1, power, r - r / power, r - power, r - power + 1, r - 1])
			{
				products.Add(high * r + low);
			}
		}

		// P-384 clears limb i with q = t_i·(2^32 + 1) mod 2^64, so a limb 0 of 2^64 − 2^33 + 1 gives q = 2^64 − 2^32 + 1, the nonzero q for
		// which q + ⌊q/2^32⌋ wraps to 0, at the bottom of the range and next to its top.
		products.UnionWith([0xFFFFFFFE00000001, limit - r + 0xFFFFFFFE00000001]);

		for (int i = 0; i < 256; ++i)
		{
			products.Add(RandomBelow(random, limit));
			products.Add(PatternedBelow(random, limit));
		}

		products.RemoveWhere(product => product < 0 || product >= limit);
		List<string> failures = [];

		foreach (BigInteger product in products)
		{
			BigInteger reduced = modulus.Reduce(product);

			if (reduced >= 2 * m || reduced % m != product * rInverse % m)
			{
				failures.Add($"{product:X} gave {reduced:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		int bits = (int)bound.GetBitLength();
		byte[] bytes = new byte[(bits + 7) / 8];
		BigInteger mask = (BigInteger.One << bits) - 1;

		while (true)
		{
			random.NextBytes(bytes);
			BigInteger value = new BigInteger(bytes, isUnsigned: true) & mask;

			if (value < bound)
			{
				return value;
			}
		}
	}

	private static BigInteger PatternedBelow(Random random, BigInteger bound)
	{
		ulong[] patterns = [0, 1, 1UL << 63, ulong.MaxValue - 1, ulong.MaxValue];
		int bits = (int)bound.GetBitLength();
		BigInteger mask = (BigInteger.One << bits) - 1;

		while (true)
		{
			BigInteger value = 0;

			for (int i = 0; i < (bits + 63) / 64; ++i)
			{
				int pattern = random.Next(patterns.Length + 1);
				ulong limb = pattern < patterns.Length ? patterns[pattern] : (ulong)random.NextInt64(long.MinValue, long.MaxValue);
				value = value << 64 | limb;
			}

			value &= mask;

			if (value < bound)
			{
				return value;
			}
		}
	}
}
