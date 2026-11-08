using CryptoBase.EllipticCurves;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

// SM2Field52 against BigInteger, with inputs anywhere in the form that its members take, limbs 0 to 3 below 2^53 and limb 4 below 2^50, as well as canonical ones: a value v also stands as v + kp for every k that fits, with limbs as large as the form allows. Every result must be in that form, and some in the tighter forms that the formulas rely on.
[InheritsTests]
internal class SM2Field52Test() : ECFieldTest<SM2Curve, SM2Field52, SM2Order>(52, 1UL << 53, 1UL << 50, BigInteger.One << 260, 1UL << 48, 10)
{
	// The column sums and Montgomery rounds keep within 64 bits for limbs below 2^56, beyond the form. Limbs of only their low byte, or of all but their low four bits, make the most negative spreads at limb i + 1 and limb i + 4, which may take limbs of the product below 0 before their carries.
	[Test]
	public async Task MultiplyTakesLimbsBelow2To56()
	{
		ulong most = (1UL << 56) - 1;
		ulong lowByte = 0xFF;
		ulong highBits = (1UL << 36) - 16;
		List<SM2Field52> values = [Limbs(most, most, most, most, most), Limbs(most, 0, most, 0, most), Limbs(0, most, 0, most, 0), Limbs(Low - 1, Low - 1, Low - 1, Low - 1, most), Limbs(lowByte, 0, 0, 0, 0), Limbs(lowByte, lowByte, lowByte, lowByte, lowByte), Limbs(highBits, highBits, highBits, highBits, highBits), Limbs(1, 0, 0, 0, 0)];
		Random random = new(2);

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(Limbs(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
			values.Add(Limbs(Next(random, 1UL << 8), Next(random, 1UL << 8), Next(random, 1UL << 8), Next(random, 1UL << 8), Next(random, 1UL << 8)));
		}

		List<string> failures = [];

		foreach (SM2Field52 x in values)
		{
			foreach (SM2Field52 y in values)
			{
				SM2Field52.Multiply(in x, in y, out SM2Field52 product);
				CheckProduct(failures, $"Multiply {ShowLimbs(x)}, {ShowLimbs(y)}", product, ValueOf(x), ValueOf(y), false);
			}

			SM2Field52.Square(in x, out SM2Field52 square);
			CheckProduct(failures, $"Square {ShowLimbs(x)}", square, ValueOf(x), ValueOf(x), false);
		}

		await Assert.That(failures).IsEmpty();
	}

	// For limbs below 2^62, limbs 0 to 3 come out below 2^52, limb 4 below 2^48 + 2^16·h + 2^10 for h = L4 >> 48, and the value below 2p. Every limb at its most, with h at its most, takes limb 1 and the carries to their largest.
	[Test]
	public async Task WeakReduceTakesLimbsBelow2To62()
	{
		ulong most = (1UL << 62) - 1;
		List<SM2Field52> values = [Limbs(most, most, most, most, most), Limbs(0, 0, 0, 0, most), Limbs(most, 0, most, 0, most), Limbs(0, most, 0, 0, most), Limbs(0, 0, 0, 0, 1UL << 48), Limbs(0, 0, 0, 0, 0), Represent(Largest, AllHigh)!.Value];
		Random random = new(3);

		for (int i = 0; i < 4 * RandomCount; ++i)
		{
			values.Add(Limbs(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
			values.Add(Limbs(Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, most)));
		}

		List<string> failures = [];

		foreach (SM2Field52 value in values)
		{
			SM2Field52.WeakReduce(in value, out SM2Field52 result);
			ulong h = value.L4 >> 48;
			BigInteger reduced = ValueOf(result);

			if (Mod(reduced) != Mod(ValueOf(value)) || reduced >= 2 * P || !IsInForm(result, Low, (1UL << 48) + (h << 16) + (1UL << 10)))
			{
				failures.Add($"WeakReduce {ShowLimbs(value)} gave {ShowLimbs(result)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// TrySquareRoot accepts a value just if it is a square, as BigInteger.ModPow decides it, and gives a root in the form whose Montgomery square is the value: for each residue v, v² and −v², which is not a square unless 0, as −1 is not a square for p ≡ 3 (mod 4), in every representation of the form.
	[Test]
	public async Task TrySquareRootFindsTheRootsOfSquares()
	{
		Random random = new(4);
		SortedSet<BigInteger> roots = [0, 1, 2, 3, P - 1, P - 2, (P - 1) / 2];
		AddLimbBoundaries(roots);

		for (int i = 0; i < RandomCount; ++i)
		{
			roots.Add(RandomBelow(random, P));
		}

		List<string> failures = [];

		foreach (BigInteger root in roots)
		{
			BigInteger square = Mod(root * root);

			foreach (BigInteger value in (BigInteger[])[square, Mod(-square)])
			{
				bool expected = BigInteger.ModPow(value, (P - 1) / 2, P) <= 1;

				foreach (SM2Field52 element in Representations(value, random))
				{
					bool found = SM2Field52.TrySquareRoot(in element, out SM2Field52 result);
					BigInteger r = ValueOf(result);

					if (found != expected || found && (Mod(r * r * RInverse) != value || !IsInForm(result)))
					{
						failures.Add($"TrySquareRoot {ShowLimbs(element)} gave {found} and {ShowLimbs(result)}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Multiply leaves limbs 0 to 3 below 2^52 and the value below x·y/2^260 + p, so limb 4 below 2^49 for inputs of the form.
	private protected override void CheckProduct(List<string> failures, string operation, in SM2Field52 actual, BigInteger x, BigInteger y)
	{
		CheckProduct(failures, operation, actual, x, y, true);
	}

	private void CheckProduct(List<string> failures, string operation, in SM2Field52 actual, BigInteger x, BigInteger y, bool inForm)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(x * y * RInverse) || value * R >= x * y + P * R || !IsInForm(actual, Low, inForm ? 1UL << 49 : ulong.MaxValue))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(x * y * RInverse):X}");
		}
	}

	// WeakReduce leaves limbs 0 to 3 below 2^52 and the value below 2p.
	private protected override void CheckReduced(List<string> failures, string operation, in SM2Field52 actual, BigInteger expected)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(expected) || value >= 2 * P || !IsInForm(actual, Low, 1UL << 49))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(expected):X}");
		}
	}
}
