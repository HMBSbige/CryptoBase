using CryptoBase.EllipticCurves;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

// P521Field58 against BigInteger. Inputs cover the whole form that the members take, limbs 0 to 7 below 2^58 and limb 8 below 2^57 + 2^6, not only canonical values: a value v also stands as v + p where that fits. Every result must be in the form. R = 1, so every value is plain.
[InheritsTests]
internal class P521Field58Test() : ECFieldTest<P521Curve, P521Field58, P521Order>(58, 1UL << 58, Top, BigInteger.One, 1UL << 57, 9)
{
	private const ulong Top = (1UL << 57) + (1UL << 6);

	// Sizes a and b up to 6 with ab ≤ 6, beyond the form: limbs 0 to 7 below a·2^58 and limb 8 below a·(2^57 + 2^6), here in thousandths. Square takes sizes up to √6.
	[Test]
	public async Task MultiplyTakesSizesWithProductUpTo6()
	{
		(int Left, int Right)[] sizes = [(1000, 6000), (6000, 1000), (2000, 3000), (3000, 2000), (1500, 4000), (4000, 1500), (2400, 2500), (2500, 2400)];
		Random random = new(2);
		List<string> failures = [];

		foreach ((int left, int right) in sizes)
		{
			foreach (P521Field58 x in Bounded(left, random))
			{
				foreach (P521Field58 y in Bounded(right, random))
				{
					P521Field58.Multiply(in x, in y, out P521Field58 product);
					CheckReduced(failures, $"Multiply {ShowLimbs(x)}, {ShowLimbs(y)}", product, ValueOf(x) * ValueOf(y));
				}
			}
		}

		foreach (int size in (int[])[1000, 2000, 2449])
		{
			foreach (P521Field58 x in Bounded(size, random))
			{
				P521Field58.Square(in x, out P521Field58 square);
				CheckReduced(failures, $"Square {ShowLimbs(x)}", square, ValueOf(x) * ValueOf(x));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// For limbs below 2^64 − 2^7, limbs 0 to 7 come out below 2^58, limb 8 below 2^57 + 2^6, and the value below 2p.
	[Test]
	public async Task WeakReduceTakesLimbsBelow2To64Less2To7()
	{
		ulong most = ulong.MaxValue - (1UL << 7);
		List<P521Field58> values = [Limbs(most, most, most, most, most, most, most, most, most), Limbs(0, 0, 0, 0, 0, 0, 0, 0, most), Limbs(most, 0, most, 0, most, 0, most, 0, most), Limbs(Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, most), Limbs(0, 0, 0, 0, 0, 0, 0, 0, 0), Sized(1000)];
		Random random = new(3);

		for (int i = 0; i < 4 * RandomCount; ++i)
		{
			values.Add(Limbs(Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most), Next(random, most)));
			values.Add(Limbs(Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, Low), Next(random, most)));
		}

		List<string> failures = [];

		foreach (P521Field58 value in values)
		{
			P521Field58.WeakReduce(in value, out P521Field58 result);
			CheckReduced(failures, $"WeakReduce {ShowLimbs(value)}", result, ValueOf(value));
		}

		await Assert.That(failures).IsEmpty();
	}

	// The formulas are identities in the field, so they hold for any coordinates, not only those of points: these take every limb at the limits of the form, with BigInteger for the reference.
	[Test]
	public async Task FormulasMatchBigIntegerForLimbsAtTheLimits()
	{
		Random random = new(8);
		List<P521Field58> values = [Sized(1000), Represent(P, AllLow)!.Value, Limbs(Low - 1, 0, Low - 1, 0, Low - 1, 0, Low - 1, 0, Top - 1), Limbs(0, Low - 1, 0, Low - 1, 0, Low - 1, 0, Low - 1, 0)];

		for (int i = 0; i < 4; ++i)
		{
			values.Add(Loose(RandomBelow(random, P), random));
		}

		List<string> failures = [];

		foreach (P521Field58 x in values)
		{
			foreach (P521Field58 y in values)
			{
				foreach (P521Field58 z in values)
				{
					JacobianPoint<P521Field58> point = new() { X = x, Y = y, Z = z };
					JacobianPoint<P521Field58> other = new() { X = z, Y = x, Z = y };
					AffinePoint<P521Field58> affine = new() { X = y, Y = z };
					P521Field58.Double(in point, out JacobianPoint<P521Field58> result);
					CheckFormula(failures, "Double", point, result, ExpectedDouble(Value(point)));
					ulong mask = P521Field58.AddDistinct(in point, in other, out result);
					CheckFormula(failures, "AddDistinct", point, result, ExpectedAdd(Value(point), Value(other), out bool equal), mask, equal);
					mask = P521Field58.AddDistinct(in point, in affine, out result);
					CheckFormula(failures, "AddDistinct affine", point, result, ExpectedAdd(Value(point), new JacobianValue(ValueOf(affine.X), ValueOf(affine.Y), 1), out equal), mask, equal);
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Below p, with residues that sit next to the limb boundaries; those up to 2^470 also stand as v + p.
	private protected override IEnumerable<BigInteger> Residues(Random random)
	{
		SortedSet<BigInteger> values = [0, 1, 2, P - 1, P - 2, Mod(Largest), Mod(Largest) - 1];
		AddLimbBoundaries(values);

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
			values.Add(RandomBelow(random, Mod(Largest) + 1));
		}

		values.RemoveWhere(value => value < 0 || value >= P);
		return values;
	}

	// The element of a size in thousandths with every limb at its most.
	private P521Field58 Sized(int size)
	{
		ulong low = Limit(size, Low);
		ulong top = Limit(size, Top);
		return Limbs(low, low, low, low, low, low, low, low, top);
	}

	// Elements of a size in thousandths at their most and at random below it.
	private IEnumerable<P521Field58> Bounded(int size, Random random)
	{
		ulong low = Limit(size, Low);
		ulong top = Limit(size, Top);
		yield return Sized(size);
		yield return Limbs(low, 0, low, 0, low, 0, low, 0, top);
		yield return Limbs(0, low, 0, low, 0, low, 0, low, 0);
		yield return Limbs(Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, Low - 1, top);

		for (int i = 0; i < 6; ++i)
		{
			yield return Limbs(Next(random, low + 1), Next(random, low + 1), Next(random, low + 1), Next(random, low + 1), Next(random, low + 1), Next(random, low + 1), Next(random, low + 1), Next(random, low + 1), Next(random, top + 1));
		}
	}

	// The largest integer below size/1000·unit.
	private static ulong Limit(int size, ulong unit)
	{
		return (ulong)(((UInt128)(uint)size * unit - 1) / 1000);
	}

	// The doubling formula of Double, step by step.
	private static JacobianValue ExpectedDouble(JacobianValue point)
	{
		BigInteger gamma = point.Y * point.Y;
		BigInteger beta = point.X * gamma;
		BigInteger delta = point.Z * point.Z;
		BigInteger alpha = 3 * (point.X - delta) * (point.X + delta);
		BigInteger x3 = Mod(alpha * alpha - 8 * beta);
		return new JacobianValue(x3, Mod(alpha * (4 * beta - x3) - 8 * gamma * gamma), Mod(2 * point.Y * point.Z));
	}

	// The addition formula of AddDistinct, step by step; equal is set when H and R are both 0.
	private static JacobianValue ExpectedAdd(JacobianValue left, JacobianValue right, out bool equal)
	{
		BigInteger z1z1 = left.Z * left.Z;
		BigInteger z2z2 = right.Z * right.Z;
		BigInteger u1 = Mod(left.X * z2z2);
		BigInteger h = Mod(right.X * z1z1 - u1);
		BigInteger s1 = Mod(left.Y * z2z2 * right.Z);
		BigInteger r = Mod(2 * (right.Y * z1z1 * left.Z - s1));
		equal = h.IsZero && r.IsZero;
		BigInteger i = 4 * h * h;
		BigInteger j = Mod(h * i);
		BigInteger v = Mod(u1 * i);
		BigInteger x3 = Mod(r * r - j - 2 * v);
		return new JacobianValue(x3, Mod(r * (v - x3) - 2 * s1 * j), Mod(2 * left.Z * right.Z * h));
	}

	private void CheckFormula(List<string> failures, string operation, in JacobianPoint<P521Field58> input, in JacobianPoint<P521Field58> actual, JacobianValue expected, ulong mask = 0, bool equal = false)
	{
		if (!IsInForm(actual.X) || !IsInForm(actual.Y) || !IsInForm(actual.Z) || Value(actual) != expected || mask != (equal ? ulong.MaxValue : 0))
		{
			failures.Add($"{operation} of ({ShowLimbs(input.X)}, {ShowLimbs(input.Y)}, {ShowLimbs(input.Z)}) gave ({ShowLimbs(actual.X)}, {ShowLimbs(actual.Y)}, {ShowLimbs(actual.Z)}) and the mask {mask:X}");
		}
	}

	// The form, the value mod p and a value below 2p, which IsZero and Export rely on.
	private protected override void CheckReduced(List<string> failures, string operation, in P521Field58 actual, BigInteger expected)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(expected) || value >= 2 * P || !IsInForm(actual))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(expected):X}");
		}
	}

	private protected override void CheckProduct(List<string> failures, string operation, in P521Field58 actual, BigInteger x, BigInteger y)
	{
		CheckReduced(failures, operation, actual, x * y);
	}
}
