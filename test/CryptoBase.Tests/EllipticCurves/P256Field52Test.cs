using CryptoBase.EllipticCurves;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

// P256Field52 against BigInteger, with inputs anywhere in the form that its members take, limbs 0 to 3 below 2^53 and limb 4 below 2^50, as well as canonical ones: a value v also stands as v + kp for every k that fits, with limbs as large as the form allows. Every result must be in that form, and some in the tighter forms that the formulas rely on.
[InheritsTests]
internal class P256Field52Test() : EcFieldTest<P256Curve, P256Field52, P256Order>(52, 1UL << 53, 1UL << 50, BigInteger.One << 260, 1UL << 48, 8)
{
	// The column sums and Montgomery rounds keep within 64 bits for limbs below 2^56, beyond the form.
	[Test]
	public async Task MultiplyTakesLimbsBelow2To56()
	{
		ulong most = (1UL << 56) - 1;
		List<P256Field52> values = [Limbs(most, most, most, most, most), Limbs(most, 0, most, 0, most), Limbs(0, most, 0, most, 0), Limbs(Low - 1, Low - 1, Low - 1, Low - 1, most)];
		Random random = new(2);

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(Limbs(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
		}

		List<string> failures = [];

		foreach (P256Field52 x in values)
		{
			foreach (P256Field52 y in values)
			{
				P256Field52.Multiply(in x, in y, out P256Field52 product);
				CheckProduct(failures, $"Multiply {ShowLimbs(x)}, {ShowLimbs(y)}", product, ValueOf(x), ValueOf(y), false);
			}

			P256Field52.Square(in x, out P256Field52 square);
			CheckProduct(failures, $"Square {ShowLimbs(x)}", square, ValueOf(x), ValueOf(x), false);
		}

		await Assert.That(failures).IsEmpty();
	}

	// For limbs below 2^62, limbs 0 to 3 come out below 2^52, limb 4 below 2^48 + 2^16·h + 2^10 for h = L4 >> 48, and the value below 2p. Limbs 1 and 3 at 0 with h at its most take them below 0 before the carries.
	[Test]
	public async Task WeakReduceTakesLimbsBelow2To62()
	{
		ulong most = (1UL << 62) - 1;
		List<P256Field52> values = [Limbs(most, most, most, most, most), Limbs(0, 0, 0, 0, most), Limbs(most, 0, most, 0, most), Limbs(0, 0, 0, 0, 1UL << 48), Limbs(0, 0, 0, 0, 0), Represent(Largest, AllHigh)!.Value];
		Random random = new(3);

		for (int i = 0; i < 4 * RandomCount; ++i)
		{
			values.Add(Limbs(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
			values.Add(Limbs(Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, most)));
		}

		List<string> failures = [];

		foreach (P256Field52 value in values)
		{
			P256Field52.WeakReduce(in value, out P256Field52 result);
			ulong h = value.L4 >> 48;
			BigInteger reduced = ValueOf(result);

			if (Mod(reduced) != Mod(ValueOf(value)) || reduced >= 2 * P || !IsInForm(result, Low, (1UL << 48) + (h << 16) + (1UL << 10)))
			{
				failures.Add($"WeakReduce {ShowLimbs(value)} gave {ShowLimbs(result)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Multiply leaves limbs 0 to 3 below 2^52 and the value below x·y/2^260 + p, so limb 4 below 2^49 for inputs of the form.
	private protected override void CheckProduct(List<string> failures, string operation, in P256Field52 actual, BigInteger x, BigInteger y)
	{
		CheckProduct(failures, operation, actual, x, y, true);
	}

	private void CheckProduct(List<string> failures, string operation, in P256Field52 actual, BigInteger x, BigInteger y, bool inForm)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(x * y * RInverse) || value * R >= x * y + P * R || !IsInForm(actual, Low, inForm ? 1UL << 49 : ulong.MaxValue))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(x * y * RInverse):X}");
		}
	}

	// WeakReduce leaves limbs 0 to 3 below 2^52 and the value below 2p.
	private protected override void CheckReduced(List<string> failures, string operation, in P256Field52 actual, BigInteger expected)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(expected) || value >= 2 * P || !IsInForm(actual, Low, 1UL << 49))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(expected):X}");
		}
	}
}
