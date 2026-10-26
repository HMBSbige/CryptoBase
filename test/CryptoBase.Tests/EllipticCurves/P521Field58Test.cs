using CryptoBase.EllipticCurves;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

// P521Field58 against BigInteger. Inputs cover the whole form that the members take, limbs 0 to 7 below 2^58 and limb 8 below 2^57 + 2^6, not only canonical values: a value v also stands as v + p where that fits. Every result must be in the form. R = 1, so every value is plain.
public class P521Field58Test
{
	private const int RandomCount = 32;

	private const ulong Low = 1UL << 58;

	private const ulong Top = (1UL << 57) + (1UL << 6);

	private static readonly BigInteger P = ModulusCase.FromLimbs(P521Field58.Modulus);

	// The largest value of the form, p + 2^470: every limb at its most.
	private static readonly BigInteger Largest = ValueOf(Sized(1000));

	private static readonly CurveCase Curve = CurveCase.Named("secp521r1");

	[Test]
	public async Task ArithmeticMatchesBigInteger()
	{
		List<string> failures = [];
		Random random = new(1);

		foreach ((P521Field58 x, P521Field58 y) in Pairs(random))
		{
			BigInteger a = ValueOf(x);
			BigInteger b = ValueOf(y);
			string operands = $"{ShowLimbs(x)}, {ShowLimbs(y)}";
			P521Field58.Multiply(in x, in y, out P521Field58 result);
			CheckReduced(failures, $"Multiply {operands}", result, a * b);
			P521Field58.Square(in x, out result);
			CheckReduced(failures, $"Square {ShowLimbs(x)}", result, a * a);
			P521Field58.Add(in x, in y, out result);
			CheckReduced(failures, $"Add {operands}", result, a + b);
			P521Field58.Subtract(in x, in y, out result);
			CheckReduced(failures, $"Subtract {operands}", result, a - b);
			P521Field58.Negate(in y, out result);
			CheckReduced(failures, $"Negate {ShowLimbs(y)}", result, -b);
			P521Field58.ToMontgomery(in x, out result);
			CheckReduced(failures, $"ToMontgomery {ShowLimbs(x)}", result, a);
			P521Field58.FromMontgomery(in x, out result);
			CheckReduced(failures, $"FromMontgomery {ShowLimbs(x)}", result, a);
		}

		await Assert.That(failures).IsEmpty();
	}

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

	// Both multiples of p in the form, 0 and p, are 0, and their neighbours are not.
	[Test]
	public async Task ZeroTestsReduceFirst()
	{
		List<string> failures = [];
		Random random = new(4);
		List<BigInteger> values = [0, 1, P - 1, P + 1, Largest, Largest - 1, Low, Low - 1];

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
		}

		foreach (BigInteger value in values)
		{
			foreach (P521Field58 x in Representations(value))
			{
				ulong expected = Mod(value).IsZero ? ulong.MaxValue : 0;

				if (P521Field58.IsZero(in x) != expected)
				{
					failures.Add($"IsZero {ShowLimbs(x)}");
				}

				foreach (P521Field58 y in Representations(value))
				{
					if (P521Field58.AreEqual(in x, in y) != ulong.MaxValue)
					{
						failures.Add($"AreEqual {ShowLimbs(x)}, {ShowLimbs(y)}");
					}
				}

				foreach (P521Field58 y in Representations(value + 1))
				{
					if (P521Field58.AreEqual(in x, in y) is not 0)
					{
						failures.Add($"AreEqual {ShowLimbs(x)}, {ShowLimbs(y)}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ExportAndInversionReduceFirst()
	{
		List<string> failures = [];
		Random random = new(5);

		foreach (BigInteger value in Residues(random))
		{
			foreach (P521Field58 x in Representations(value))
			{
				byte[] exported = new byte[66];
				P521Field58.Export(in x, exported);

				if (!exported.AsSpan().SequenceEqual(Curve.EncodeCoordinate(value)))
				{
					failures.Add($"Export {ShowLimbs(x)}");
				}

				// value^(p − 2) also maps 0 to 0.
				BigInteger inverse = BigInteger.ModPow(value, P - 2, P);
				P521Field58.Invert(in x, out P521Field58 result);
				CheckCanonical(failures, $"Invert {ShowLimbs(x)}", result, inverse);
				P521Field58.InvertVariableTime(in x, out result);
				CheckCanonical(failures, $"InvertVariableTime {ShowLimbs(x)}", result, inverse);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ImportsGiveCanonicalLimbs()
	{
		List<string> failures = [];
		Random random = new(6);

		foreach (BigInteger value in Residues(random))
		{
			ulong[] limbs = [.. Enumerable.Range(0, 9).Select(i => (ulong)(value >> 64 * i & ulong.MaxValue))];
			P521Field58.FromLimbs(limbs, out P521Field58 element);
			CheckCanonical(failures, $"FromLimbs {value:X}", element, value);

			if (!P521Field58.TryImport(Curve.EncodeCoordinate(value), out element))
			{
				failures.Add($"TryImport {value:X} failed");
			}

			CheckCanonical(failures, $"TryImport {value:X}", element, value);
		}

		foreach (BigInteger value in (BigInteger[])[P, P + 1, (BigInteger.One << 528) - 1])
		{
			if (P521Field58.TryImport(Curve.EncodeCoordinate(value), out P521Field58 element) || ValueOf(element) != 0)
			{
				failures.Add($"TryImport {value:X} accepted or left {ShowLimbs(element)}");
			}
		}

		CheckCanonical(failures, "One", P521Field58.One, 1);
		await Assert.That(failures).IsEmpty();
	}

	// The formulas leave out reductions between steps, so their inputs take each coordinate as v and as v + p where that fits the form, including a Z of 0 written as p.
	[Test]
	public async Task FormulasMatchTheReferenceForCoordinatesAtTheLimits()
	{
		EcReference reference = Curve.Reference;
		Random random = new(7);
		List<string> failures = [];

		foreach ((CurvePoint? left, CurvePoint? right) in EcGroupTest.Pairs(reference, random))
		{
			string operation = $"{Show(left)} + {Show(right)}";
			JacobianPoint<P521Field58> x = Loose(reference.RandomizeJacobian(left, random), random);
			JacobianPoint<P521Field58> y = Loose(reference.RandomizeJacobian(right, random), random);
			P521Field58.Double(in x, out JacobianPoint<P521Field58> twice);
			CheckPoint(failures, reference, $"2 · {Show(left)}", twice, reference.Add(left, left));
			EcGroup<P521Curve, P521Field58, P521Order>.Add(in x, in y, out JacobianPoint<P521Field58> sum);
			CheckPoint(failures, reference, operation, sum, reference.Add(left, right));

			if (right is null)
			{
				continue;
			}

			AffinePoint<P521Field58> affine = Loose(right, random);
			EcGroup<P521Curve, P521Field58, P521Order>.Add(in x, in affine, out sum);
			CheckPoint(failures, reference, $"{operation}, affine", sum, reference.Add(left, right));

			if (left is null)
			{
				continue;
			}

			ulong mask = P521Field58.AddDistinct(in x, in y, out sum);
			CheckDistinct(failures, reference, operation, mask, sum, left, right);
			mask = P521Field58.AddDistinct(in x, in affine, out sum);
			CheckDistinct(failures, reference, $"{operation}, affine", mask, sum, left, right);
		}

		await Assert.That(failures).IsEmpty();
	}

	// The formulas are identities in the field, so they hold for any coordinates, not only those of points: these take every limb at the limits of the form, with BigInteger for the reference.
	[Test]
	public async Task FormulasMatchBigIntegerForLimbsAtTheLimits()
	{
		Random random = new(8);
		List<P521Field58> values = [Sized(1000), Represent(P)!.Value, Limbs(Low - 1, 0, Low - 1, 0, Low - 1, 0, Low - 1, 0, Top - 1), Limbs(0, Low - 1, 0, Low - 1, 0, Low - 1, 0, Low - 1, 0)];

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

	// Each result is the next input, over a long chain of doublings and complete additions of G and of 2kG to kG, checked against the reference along the way.
	[Test]
	public async Task LongChainsOfFormulasStayInForm()
	{
		EcReference reference = Curve.Reference;
		BigInteger n = Curve.Order;
		Random random = new(9);
		AffinePoint<P521Field58> generator = Loose(reference.Generator, random);
		JacobianPoint<P521Field58> point = Loose(reference.RandomizeJacobian(reference.Generator, random), random);
		BigInteger k = 1;
		List<string> failures = [];

		for (int i = 1; i <= 4000 && failures.Count is 0; ++i)
		{
			switch (random.Next(4))
			{
				case 0:
					EcGroup<P521Curve, P521Field58, P521Order>.Add(in point, in generator, out point);
					k += 1;
					break;
				case 1:
					P521Field58.Double(in point, out JacobianPoint<P521Field58> twice);
					EcGroup<P521Curve, P521Field58, P521Order>.Add(in point, in twice, out point);
					k *= 3;
					break;
				default:
					P521Field58.Double(in point, out point);
					k *= 2;
					break;
			}

			k %= n;

			if (!IsInForm(point.X) || !IsInForm(point.Y) || !IsInForm(point.Z))
			{
				failures.Add($"step {i} left the form");
			}

			if (i % 250 is 0)
			{
				CheckPoint(failures, reference, $"step {i}", point, reference.Multiply(reference.Generator, k));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The field members chain as well: each result is the next input, and the inputs keep to the form.
	[Test]
	public async Task LongChainsOfArithmeticStayInForm()
	{
		Random random = new(10);
		P521Field58 x = Sized(1000);
		P521Field58 y = Loose(RandomBelow(random, P), random);
		BigInteger a = Mod(ValueOf(x));
		BigInteger b = Mod(ValueOf(y));
		List<string> failures = [];

		for (int i = 0; i < 20000 && failures.Count is 0; ++i)
		{
			switch (random.Next(6))
			{
				case 0:
					P521Field58.Multiply(in x, in y, out x);
					a = a * b % P;
					break;
				case 1:
					P521Field58.Square(in x, out x);
					a = a * a % P;
					break;
				case 2:
					P521Field58.Add(in x, in y, out x);
					a = (a + b) % P;
					break;
				case 3:
					P521Field58.Subtract(in y, in x, out x);
					a = Mod(b - a);
					break;
				case 4:
					P521Field58.Negate(in x, out x);
					a = Mod(-a);
					break;
				default:
					(x, y, a, b) = (y, x, b, a);
					break;
			}

			if (Mod(ValueOf(x)) != a || !IsInForm(x))
			{
				failures.Add($"step {i} gave {ShowLimbs(x)}, expected {a:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Below p, with residues that sit next to the limb boundaries; those up to 2^470 also stand as v + p.
	private static IEnumerable<BigInteger> Residues(Random random)
	{
		SortedSet<BigInteger> values = [0, 1, 2, P - 1, P - 2, Mod(Largest), Mod(Largest) - 1];

		for (int k = 1; k <= 8; ++k)
		{
			BigInteger power = BigInteger.One << 58 * k;
			values.UnionWith([power - 1, power, power + 1, P - power, P - power + 1]);
		}

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
			values.Add(RandomBelow(random, Mod(Largest) + 1));
		}

		values.RemoveWhere(value => value < 0 || value >= P);
		return values;
	}

	private static IEnumerable<(P521Field58 Left, P521Field58 Right)> Pairs(Random random)
	{
		BigInteger[] residues = [.. Residues(random)];

		foreach (BigInteger left in residues)
		{
			foreach (BigInteger right in residues)
			{
				yield return (Canonical(left), Canonical(right));
				yield return (Highest(left), Highest(right));
			}
		}

		yield return (Sized(1000), Sized(1000));
	}

	// value and value + p, where it fits the form. Limbs 0 to 7 below 2^58 leave no other representations.
	private static IEnumerable<P521Field58> Representations(BigInteger value)
	{
		value = Mod(value);

		for (BigInteger u = value; u <= Largest; u += P)
		{
			yield return Represent(u)!.Value;
		}
	}

	private static P521Field58 Canonical(BigInteger value)
	{
		return Represent(Mod(value))!.Value;
	}

	private static P521Field58 Highest(BigInteger value)
	{
		return Representations(value).Last();
	}

	private static P521Field58 Loose(BigInteger value, Random random)
	{
		P521Field58[] representations = [.. Representations(value)];
		return representations[random.Next(representations.Length)];
	}

	private static JacobianPoint<P521Field58> Loose(JacobianValue value, Random random)
	{
		return new JacobianPoint<P521Field58> { X = Loose(value.X, random), Y = Loose(value.Y, random), Z = Loose(value.Z, random) };
	}

	private static AffinePoint<P521Field58> Loose(CurvePoint point, Random random)
	{
		return new AffinePoint<P521Field58> { X = Loose(point.X, random), Y = Loose(point.Y, random) };
	}

	// Limbs of u, limbs 0 to 7 below 2^58; null if limb 8 does not fit the form.
	private static P521Field58? Represent(BigInteger u)
	{
		ulong[] limbs = new ulong[9];

		for (int i = 0; i < 8; ++i)
		{
			limbs[i] = (ulong)(u & Low - 1);
			u >>= 58;
		}

		if (u >= Top)
		{
			return null;
		}

		return Limbs(limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6], limbs[7], (ulong)u);
	}

	// The element of a size in thousandths with every limb at its most.
	private static P521Field58 Sized(int size)
	{
		ulong low = Limit(size, Low);
		ulong top = Limit(size, Top);
		return Limbs(low, low, low, low, low, low, low, low, top);
	}

	// Elements of a size in thousandths at their most and at random below it.
	private static IEnumerable<P521Field58> Bounded(int size, Random random)
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

	private static P521Field58 Limbs(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4, ulong l5, ulong l6, ulong l7, ulong l8)
	{
		return new P521Field58 { L0 = l0, L1 = l1, L2 = l2, L3 = l3, L4 = l4, L5 = l5, L6 = l6, L7 = l7, L8 = l8 };
	}

	private static BigInteger ValueOf(in P521Field58 value)
	{
		ulong[] limbs = [value.L0, value.L1, value.L2, value.L3, value.L4, value.L5, value.L6, value.L7, value.L8];
		BigInteger result = 0;

		for (int i = 8; i >= 0; --i)
		{
			result = (result << 58) + limbs[i];
		}

		return result;
	}

	private static JacobianValue Value(in JacobianPoint<P521Field58> point)
	{
		return new JacobianValue(Mod(ValueOf(point.X)), Mod(ValueOf(point.Y)), Mod(ValueOf(point.Z)));
	}

	private static bool IsInForm(in P521Field58 value)
	{
		return value.L0 < Low && value.L1 < Low && value.L2 < Low && value.L3 < Low && value.L4 < Low && value.L5 < Low && value.L6 < Low && value.L7 < Low && value.L8 < Top;
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

	private static void CheckFormula(List<string> failures, string operation, in JacobianPoint<P521Field58> input, in JacobianPoint<P521Field58> actual, JacobianValue expected, ulong mask = 0, bool equal = false)
	{
		if (!IsInForm(actual.X) || !IsInForm(actual.Y) || !IsInForm(actual.Z) || Value(actual) != expected || mask != (equal ? ulong.MaxValue : 0))
		{
			failures.Add($"{operation} of ({ShowLimbs(input.X)}, {ShowLimbs(input.Y)}, {ShowLimbs(input.Z)}) gave ({ShowLimbs(actual.X)}, {ShowLimbs(actual.Y)}, {ShowLimbs(actual.Z)}) and the mask {mask:X}");
		}
	}

	// The form, the value mod p and a value below 2p, which IsZero and Export rely on.
	private static void CheckReduced(List<string> failures, string operation, in P521Field58 actual, BigInteger expected)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(expected) || value >= 2 * P || !IsInForm(actual))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(expected):X}");
		}
	}

	private static void CheckCanonical(List<string> failures, string operation, in P521Field58 actual, BigInteger expected)
	{
		if (ValueOf(actual) != expected || !IsInForm(actual) || actual.L8 >= 1UL << 57)
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {expected:X}");
		}
	}

	private static void CheckPoint(List<string> failures, EcReference reference, string operation, in JacobianPoint<P521Field58> actual, CurvePoint? expected)
	{
		if (!IsInForm(actual.X) || !IsInForm(actual.Y) || !IsInForm(actual.Z))
		{
			failures.Add($"{operation} gave ({ShowLimbs(actual.X)}, {ShowLimbs(actual.Y)}, {ShowLimbs(actual.Z)}), out of the form");
		}

		EcTestUtils.CheckPoint(failures, reference, operation, Value(actual), expected);
	}

	// Equal points give (0, 0, 0) and set the mask; any others give their sum.
	private static void CheckDistinct(List<string> failures, EcReference reference, string operation, ulong mask, in JacobianPoint<P521Field58> actual, CurvePoint left, CurvePoint right)
	{
		bool equal = left == right;

		if (mask != (equal ? ulong.MaxValue : 0))
		{
			failures.Add($"AddDistinct {operation} gave the mask {mask:X}");
		}

		if (!equal)
		{
			CheckPoint(failures, reference, $"AddDistinct {operation}", actual, reference.Add(left, right));
		}
		else if (Value(actual) != new JacobianValue(0, 0, 0))
		{
			failures.Add($"AddDistinct {operation} gave {Value(actual)}, expected (0, 0, 0)");
		}
	}

	private static BigInteger Mod(BigInteger value)
	{
		BigInteger remainder = value % P;
		return remainder.Sign < 0 ? remainder + P : remainder;
	}

	private static ulong Next(Random random, ulong bound)
	{
		return (ulong)random.NextInt64(long.MinValue, long.MaxValue) % bound;
	}

	private static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		return EcReference.RandomBelow(random, bound);
	}

	private static string ShowLimbs(in P521Field58 value)
	{
		return $"[{value.L0:X}, {value.L1:X}, {value.L2:X}, {value.L3:X}, {value.L4:X}, {value.L5:X}, {value.L6:X}, {value.L7:X}, {value.L8:X}]";
	}
}
