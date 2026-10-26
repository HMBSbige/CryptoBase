using CryptoBase.EllipticCurves;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

// P256Field52 against BigInteger, with inputs anywhere in the form that its members take, limbs 0 to 3 below 2^53 and limb 4 below 2^50, as well as canonical ones: a value v also stands as v + kp for every k that fits, with limbs as large as the form allows. Every result must be in that form, and some in the tighter forms that the formulas rely on.
public class P256Field52Test
{
	private const int RandomCount = 32;

	private const ulong Low = 1UL << 52;

	private static readonly BigInteger P = ModulusCase.FromLimbs(P256Field52.Modulus);

	private static readonly BigInteger R = BigInteger.One << 260;

	private static readonly BigInteger RInverse = BigInteger.ModPow(R, P - 2, P);

	// The largest value of the form: every limb at its most.
	private static readonly BigInteger Largest = ValueOf(Limbs(2 * Low - 1, 2 * Low - 1, 2 * Low - 1, 2 * Low - 1, (1UL << 50) - 1));

	private static readonly CurveCase Curve = CurveCase.Named("secp256r1");

	[Test]
	public async Task ArithmeticMatchesBigInteger()
	{
		List<string> failures = [];
		Random random = new(1);

		foreach ((P256Field52 x, P256Field52 y) in Pairs(random))
		{
			BigInteger a = ValueOf(x);
			BigInteger b = ValueOf(y);
			string operands = $"{ShowLimbs(x)}, {ShowLimbs(y)}";
			P256Field52.Multiply(in x, in y, out P256Field52 product);
			CheckProduct(failures, $"Multiply {operands}", product, a, b);
			P256Field52.Square(in x, out product);
			CheckProduct(failures, $"Square {ShowLimbs(x)}", product, a, a);
			P256Field52.Add(in x, in y, out P256Field52 sum);
			CheckReduced(failures, $"Add {operands}", sum, a + b);
			P256Field52.Subtract(in x, in y, out P256Field52 difference);
			CheckReduced(failures, $"Subtract {operands}", difference, a - b);
			P256Field52.Negate(in y, out P256Field52 negated);
			CheckReduced(failures, $"Negate {ShowLimbs(y)}", negated, -b);
			P256Field52.ToMontgomery(in x, out P256Field52 montgomery);
			CheckProduct(failures, $"ToMontgomery {ShowLimbs(x)}", montgomery, a, R * R % P);
			P256Field52.FromMontgomery(in x, out P256Field52 plain);
			CheckProduct(failures, $"FromMontgomery {ShowLimbs(x)}", plain, a, 1);
		}

		await Assert.That(failures).IsEmpty();
	}

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

	// Every multiple of p in the form is 0, and its neighbours are not.
	[Test]
	public async Task ZeroTestsReduceFirst()
	{
		List<string> failures = [];
		Random random = new(4);
		List<BigInteger> values = [0, 1, P - 1, P + 1, 2 * P - 1, 2 * P + 1, Largest];

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
		}

		foreach (BigInteger value in values)
		{
			foreach (P256Field52 x in Representations(value, random))
			{
				ulong expected = Mod(value).IsZero ? ulong.MaxValue : 0;

				if (P256Field52.IsZero(in x) != expected)
				{
					failures.Add($"IsZero {ShowLimbs(x)}");
				}

				foreach (P256Field52 y in Representations(value, random))
				{
					if (P256Field52.AreEqual(in x, in y) != ulong.MaxValue)
					{
						failures.Add($"AreEqual {ShowLimbs(x)}, {ShowLimbs(y)}");
					}
				}

				foreach (P256Field52 y in Representations(value + 1, random))
				{
					if (P256Field52.AreEqual(in x, in y) is not 0)
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
			foreach (P256Field52 x in Representations(value, random))
			{
				byte[] exported = new byte[32];
				P256Field52.Export(in x, exported);

				if (!exported.AsSpan().SequenceEqual(Curve.EncodeCoordinate(value)))
				{
					failures.Add($"Export {ShowLimbs(x)}");
				}

				// value = aR stands for a, so the inverse a⁻¹R is value⁻¹R²; value^(p − 2) also maps 0 to 0.
				BigInteger inverse = BigInteger.ModPow(value, P - 2, P) * R % P * R % P;
				P256Field52.Invert(in x, out P256Field52 result);
				CheckCanonical(failures, $"Invert {ShowLimbs(x)}", result, inverse);
				P256Field52.InvertVariableTime(in x, out result);
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
			ulong[] limbs = [.. Enumerable.Range(0, 4).Select(i => (ulong)(value >> 64 * i & ulong.MaxValue))];
			P256Field52.FromLimbs(limbs, out P256Field52 element);
			CheckCanonical(failures, $"FromLimbs {value:X}", element, value);

			if (!P256Field52.TryImport(Curve.EncodeCoordinate(value), out element))
			{
				failures.Add($"TryImport {value:X} failed");
			}

			CheckCanonical(failures, $"TryImport {value:X}", element, value);
		}

		foreach (BigInteger value in (BigInteger[])[P, P + 1, (BigInteger.One << 256) - 1])
		{
			if (P256Field52.TryImport(Curve.EncodeCoordinate(value), out P256Field52 element) || ValueOf(element) != 0)
			{
				failures.Add($"TryImport {value:X} accepted or left {ShowLimbs(element)}");
			}
		}

		CheckCanonical(failures, "One", P256Field52.One, R % P);
		await Assert.That(failures).IsEmpty();
	}

	// The formulas leave out reductions between steps, so their inputs take every coordinate at the limits of the form, including a Z of 0 written as a multiple of p.
	[Test]
	public async Task FormulasMatchTheReferenceForCoordinatesAtTheLimits()
	{
		EcReference reference = Curve.Reference;
		Random random = new(7);
		List<string> failures = [];

		foreach ((CurvePoint? left, CurvePoint? right) in EcGroupTest.Pairs(reference, random))
		{
			string operation = $"{Show(left)} + {Show(right)}";
			JacobianPoint<P256Field52> x = Loose(reference.RandomizeJacobian(left, random), random);
			JacobianPoint<P256Field52> y = Loose(reference.RandomizeJacobian(right, random), random);
			P256Field52.Double(in x, out JacobianPoint<P256Field52> twice);
			CheckPoint(failures, reference, $"2 · {Show(left)}", twice, reference.Add(left, left));
			EcGroup<P256Curve, P256Field52, P256Order>.Add(in x, in y, out JacobianPoint<P256Field52> sum);
			CheckPoint(failures, reference, operation, sum, reference.Add(left, right));

			if (right is null)
			{
				continue;
			}

			AffinePoint<P256Field52> affine = Loose(right, random);
			EcGroup<P256Curve, P256Field52, P256Order>.Add(in x, in affine, out sum);
			CheckPoint(failures, reference, $"{operation}, affine", sum, reference.Add(left, right));

			if (left is null)
			{
				continue;
			}

			ulong mask = P256Field52.AddDistinct(in x, in y, out sum);
			CheckDistinct(failures, reference, operation, mask, sum, left, right);
			mask = P256Field52.AddDistinct(in x, in affine, out sum);
			CheckDistinct(failures, reference, $"{operation}, affine", mask, sum, left, right);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Results feed the next step unreduced, for thousands of steps: doublings and complete additions of G and of 2kG to kG, checked against the reference along the way.
	[Test]
	public async Task LongChainsOfFormulasStayInForm()
	{
		EcReference reference = Curve.Reference;
		BigInteger n = Curve.Order;
		Random random = new(8);
		AffinePoint<P256Field52> generator = Loose(reference.Generator, random);
		JacobianPoint<P256Field52> point = Loose(reference.RandomizeJacobian(reference.Generator, random), random);
		BigInteger k = 1;
		List<string> failures = [];

		for (int i = 1; i <= 4000 && failures.Count is 0; ++i)
		{
			switch (random.Next(4))
			{
				case 0:
					EcGroup<P256Curve, P256Field52, P256Order>.Add(in point, in generator, out point);
					k += 1;
					break;
				case 1:
					P256Field52.Double(in point, out JacobianPoint<P256Field52> twice);
					EcGroup<P256Curve, P256Field52, P256Order>.Add(in point, in twice, out point);
					k *= 3;
					break;
				default:
					P256Field52.Double(in point, out point);
					k *= 2;
					break;
			}

			k %= n;

			if (!IsInForm(point.X, 2 * Low, 1UL << 50) || !IsInForm(point.Y, 2 * Low, 1UL << 50) || !IsInForm(point.Z, 2 * Low, 1UL << 50))
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
		Random random = new(9);
		P256Field52 x = Represent(Largest, AllHigh)!.Value;
		P256Field52 y = Loose(RandomBelow(random, P), random);
		BigInteger a = Mod(ValueOf(x));
		BigInteger b = Mod(ValueOf(y));
		List<string> failures = [];

		for (int i = 0; i < 20000 && failures.Count is 0; ++i)
		{
			switch (random.Next(6))
			{
				case 0:
					P256Field52.Multiply(in x, in y, out x);
					a = a * b * RInverse % P;
					break;
				case 1:
					P256Field52.Square(in x, out x);
					a = a * a * RInverse % P;
					break;
				case 2:
					P256Field52.Add(in x, in y, out x);
					a = (a + b) % P;
					break;
				case 3:
					P256Field52.Subtract(in y, in x, out x);
					a = Mod(b - a);
					break;
				case 4:
					P256Field52.Negate(in x, out x);
					a = Mod(-a);
					break;
				default:
					(x, y, a, b) = (y, x, b, a);
					break;
			}

			if (Mod(ValueOf(x)) != a || !IsInForm(x, 2 * Low, 1UL << 50))
			{
				failures.Add($"step {i} gave {ShowLimbs(x)}, expected {a:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static readonly bool[] AllHigh = [true, true, true, true];

	private static readonly bool[] AllLow = [false, false, false, false];

	// Below p, with residues that sit next to the limb boundaries.
	private static IEnumerable<BigInteger> Residues(Random random)
	{
		SortedSet<BigInteger> values = [0, 1, 2, P - 1, P - 2, R % P, R * R % P, (BigInteger.One << 256) - P, Mod(Largest)];

		for (int k = 1; k <= 4; ++k)
		{
			BigInteger power = BigInteger.One << 52 * k;
			values.UnionWith([power - 1, power, power + 1, P - power, P - power + 1]);
		}

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
		}

		values.RemoveWhere(value => value < 0 || value >= P);
		return values;
	}

	private static IEnumerable<(P256Field52 Left, P256Field52 Right)> Pairs(Random random)
	{
		BigInteger[] residues = [.. Residues(random)];

		foreach (BigInteger left in residues)
		{
			foreach (BigInteger right in residues)
			{
				yield return (Canonical(left), Canonical(right));
				yield return (Loose(left, random), Loose(right, random));
				yield return (Highest(left), Highest(right));
			}
		}
	}

	// The representations of value + kp in the form, for every k, with limbs 0 to 3 at 2^52 or more where they can be, below 2^52, or either at random.
	private static IEnumerable<P256Field52> Representations(BigInteger value, Random random)
	{
		value = Mod(value);

		for (BigInteger u = value; u <= Largest; u += P)
		{
			bool[] mixed = [.. Enumerable.Range(0, 4).Select(_ => random.Next(2) is 0)];

			foreach (bool[] high in (bool[][])[AllLow, AllHigh, mixed])
			{
				if (Represent(u, high) is { } element)
				{
					yield return element;
				}
			}
		}
	}

	private static P256Field52 Canonical(BigInteger value)
	{
		return Represent(Mod(value), AllLow)!.Value;
	}

	// The representation with the largest value and limbs 0 to 3 at 2^52 or more where they can be.
	private static P256Field52 Highest(BigInteger value)
	{
		BigInteger u = Mod(value);
		u += (Largest - u) / P * P;
		return Represent(u, AllHigh) ?? Represent(u, AllLow)!.Value;
	}

	private static P256Field52 Loose(BigInteger value, Random random)
	{
		P256Field52[] representations = [.. Representations(value, random)];
		return representations[random.Next(representations.Length)];
	}

	// Montgomery coordinates, loose.
	private static JacobianPoint<P256Field52> Loose(JacobianValue value, Random random)
	{
		return new JacobianPoint<P256Field52> { X = Loose(value.X * R, random), Y = Loose(value.Y * R, random), Z = Loose(value.Z * R, random) };
	}

	private static AffinePoint<P256Field52> Loose(CurvePoint point, Random random)
	{
		return new AffinePoint<P256Field52> { X = Loose(point.X * R, random), Y = Loose(point.Y * R, random) };
	}

	// Limbs of u, each of 0 to 3 taking an extra 2^52 from the limb above where high says so and u allows; null if limb 4 does not fit the form.
	private static P256Field52? Represent(BigInteger u, bool[] high)
	{
		ulong[] limbs = new ulong[5];

		for (int i = 0; i < 4; ++i)
		{
			BigInteger limb = u & Low - 1;

			if (high[i] && u >= limb + Low)
			{
				limb += Low;
			}

			limbs[i] = (ulong)limb;
			u = u - limb >> 52;
		}

		if (u >= 1UL << 50)
		{
			return null;
		}

		return Limbs(limbs[0], limbs[1], limbs[2], limbs[3], (ulong)u);
	}

	private static P256Field52 Limbs(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4)
	{
		return new P256Field52 { L0 = l0, L1 = l1, L2 = l2, L3 = l3, L4 = l4 };
	}

	private static BigInteger ValueOf(in P256Field52 value)
	{
		return value.L0 + ((BigInteger)value.L1 << 52) + ((BigInteger)value.L2 << 104) + ((BigInteger)value.L3 << 156) + ((BigInteger)value.L4 << 208);
	}

	// The plain coordinates of the Montgomery ones.
	private static JacobianValue Value(in JacobianPoint<P256Field52> point)
	{
		return new JacobianValue(Mod(ValueOf(point.X) * RInverse), Mod(ValueOf(point.Y) * RInverse), Mod(ValueOf(point.Z) * RInverse));
	}

	private static bool IsInForm(in P256Field52 value, ulong low, ulong top)
	{
		return value.L0 < low && value.L1 < low && value.L2 < low && value.L3 < low && value.L4 < top;
	}

	// Multiply leaves limbs 0 to 3 below 2^52 and the value below x·y/2^260 + p, so limb 4 below 2^49 for inputs of the form.
	private static void CheckProduct(List<string> failures, string operation, in P256Field52 actual, BigInteger x, BigInteger y, bool inForm = true)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(x * y * RInverse) || value * R >= x * y + P * R || !IsInForm(actual, Low, inForm ? 1UL << 49 : ulong.MaxValue))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(x * y * RInverse):X}");
		}
	}

	// WeakReduce leaves limbs 0 to 3 below 2^52 and the value below 2p.
	private static void CheckReduced(List<string> failures, string operation, in P256Field52 actual, BigInteger expected)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(expected) || value >= 2 * P || !IsInForm(actual, Low, 1UL << 49))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(expected):X}");
		}
	}

	private static void CheckCanonical(List<string> failures, string operation, in P256Field52 actual, BigInteger expected)
	{
		if (ValueOf(actual) != expected || !IsInForm(actual, Low, 1UL << 48))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {expected:X}");
		}
	}

	private static void CheckPoint(List<string> failures, EcReference reference, string operation, in JacobianPoint<P256Field52> actual, CurvePoint? expected)
	{
		if (!IsInForm(actual.X, 2 * Low, 1UL << 50) || !IsInForm(actual.Y, 2 * Low, 1UL << 50) || !IsInForm(actual.Z, 2 * Low, 1UL << 50))
		{
			failures.Add($"{operation} gave ({ShowLimbs(actual.X)}, {ShowLimbs(actual.Y)}, {ShowLimbs(actual.Z)}), out of the form");
		}

		EcTestUtils.CheckPoint(failures, reference, operation, Value(actual), expected);
	}

	// Equal points give (0, 0, 0) and set the mask; any others give their sum.
	private static void CheckDistinct(List<string> failures, EcReference reference, string operation, ulong mask, in JacobianPoint<P256Field52> actual, CurvePoint left, CurvePoint right)
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

	private static string ShowLimbs(in P256Field52 value)
	{
		return $"[{value.L0:X}, {value.L1:X}, {value.L2:X}, {value.L3:X}, {value.L4:X}]";
	}
}
