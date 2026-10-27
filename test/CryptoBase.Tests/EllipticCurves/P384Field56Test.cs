using CryptoBase.EllipticCurves;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

// P384Field56 against BigInteger, with inputs anywhere in the form that its members take, limbs 0 to 5 below 2^57 and limb 6 below 2^50, as well as canonical ones: a value v also stands as v + kp for every k that fits, with limbs as large as the form allows. Every result must be in that form, and some in the tighter forms that the formulas rely on.
[InheritsTests]
internal class P384Field56Test() : EcFieldTest<P384Curve, P384Field56, P384Order>(56, 1UL << 57, 1UL << 50, BigInteger.One << 392, 1UL << 48, 8)
{
	// What WeakReduce leaves the value below, 2^384 + 2^342, which is below 2p.
	private static readonly BigInteger ReducedBound = (BigInteger.One << 384) + (BigInteger.One << 342);

	// Multiply carries the left limbs first, so its column sums and Montgomery rounds keep within 64 bits for a left in limbs below 2^63 with a value below 2^392 and a right in limbs below 2^60, beyond the form and the bounds of the formulas.
	[Test]
	public async Task MultiplyTakesLeftBelow2To392()
	{
		ulong most = (1UL << 63) - 1;
		ulong wide = 5 * Low - 1;
		List<P384Field56> lefts = [Topped(most, most, most, most, most, most), Topped(0, most, 0, most, 0, most), Topped(most, 0, most, 0, most, 0), Topped(wide, wide, wide, wide, wide, wide), Topped(Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1), Same(0)];
		ulong right = (1UL << 60) - 1;
		List<P384Field56> rights = [Same(right), Limbs(right, 0, right, 0, right, 0, right), Limbs(0, right, 0, right, 0, right, 0), Same(wide), Same(0)];
		Random random = new(2);

		for (int i = 0; i < RandomCount; ++i)
		{
			lefts.Add(Topped(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
			rights.Add(Limbs(Next(random, right), Next(random, right), Next(random, right), Next(random, right), Next(random, right), Next(random, right), Next(random, right)));
		}

		List<string> failures = [];

		foreach (P384Field56 x in lefts)
		{
			foreach (P384Field56 y in rights)
			{
				P384Field56.Multiply(in x, in y, out P384Field56 product);
				CheckProduct(failures, $"Multiply {ShowLimbs(x)}, {ShowLimbs(y)}", product, ValueOf(x), ValueOf(y), false);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The column sums and Montgomery rounds of Square keep within 64 bits for limbs below 2^58, beyond the form.
	[Test]
	public async Task SquareTakesLimbsBelow2To58()
	{
		ulong most = (1UL << 58) - 1;
		List<P384Field56> values = [Same(most), Limbs(most, 0, most, 0, most, 0, most), Limbs(0, most, 0, most, 0, most, 0), Limbs(Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, most)];
		Random random = new(2);

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(Limbs(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
		}

		List<string> failures = [];

		foreach (P384Field56 x in values)
		{
			P384Field56.Square(in x, out P384Field56 square);
			CheckProduct(failures, $"Square {ShowLimbs(x)}", square, ValueOf(x), ValueOf(x), false);
		}

		await Assert.That(failures).IsEmpty();
	}

	// For limbs below 2^62, limbs 0 to 5 come out below 2^56, limb 6 at most 2^48 + 2^6, and the value below 2^384 + 2^342. Limb 0 at 0 with h = L6 >> 48 at its most takes it below 0 before the carries.
	[Test]
	public async Task WeakReduceTakesLimbsBelow2To62()
	{
		ulong most = (1UL << 62) - 1;
		List<P384Field56> values = [Same(most), Limbs(0, 0, 0, 0, 0, 0, most), Limbs(0, most, 0, most, 0, most, most), Limbs(0, 0, 0, 0, 0, 0, 1UL << 48), Same(0), Represent(Largest, AllHigh)!.Value];
		Random random = new(3);

		for (int i = 0; i < 4 * RandomCount; ++i)
		{
			values.Add(Limbs(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
			values.Add(Limbs(Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, most)));
		}

		List<string> failures = [];

		foreach (P384Field56 value in values)
		{
			P384Field56.WeakReduce(in value, out P384Field56 result);
			BigInteger reduced = ValueOf(result);

			if (Mod(reduced) != Mod(ValueOf(value)) || reduced >= ReducedBound || !IsInForm(result, Low, (1UL << 48) + (1UL << 6) + 1))
			{
				failures.Add($"WeakReduce {ShowLimbs(value)} gave {ShowLimbs(result)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Limbs 0 to 5 as given and limb 6 at the most that keeps the value below 2^392.
	private P384Field56 Topped(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4, ulong l5)
	{
		BigInteger rest = ValueOf(Limbs(l0, l1, l2, l3, l4, l5, 0));
		return Limbs(l0, l1, l2, l3, l4, l5, (ulong)(R - 1 - rest >> 336));
	}

	private static P384Field56 Same(ulong limb)
	{
		return Limbs(limb, limb, limb, limb, limb, limb, limb);
	}

	// Multiply leaves limbs 0 to 5 below 2^56 and the value below x·y/2^392 + p, so limb 6 below 2^48 + 2^45 for inputs of the form.
	private protected override void CheckProduct(List<string> failures, string operation, in P384Field56 actual, BigInteger x, BigInteger y)
	{
		CheckProduct(failures, operation, actual, x, y, true);
	}

	private void CheckProduct(List<string> failures, string operation, in P384Field56 actual, BigInteger x, BigInteger y, bool inForm)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(x * y * RInverse) || value * R >= x * y + P * R || !IsInForm(actual, Low, inForm ? (1UL << 48) + (1UL << 45) : ulong.MaxValue))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(x * y * RInverse):X}");
		}
	}

	// WeakReduce leaves limbs 0 to 5 below 2^56 and the value below 2^384 + 2^342.
	private protected override void CheckReduced(List<string> failures, string operation, in P384Field56 actual, BigInteger expected)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(expected) || value >= ReducedBound || !IsInForm(actual, Low, (1UL << 48) + (1UL << 6) + 1))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(expected):X}");
		}
	}
}
