using CryptoBase.EllipticCurves;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

// P384Field56 against BigInteger, with inputs anywhere in the form that its members take, limbs 0 to 5 below 2^57 and limb 6 below 2^50, as well as canonical ones: a value v also stands as v + kp for every k that fits, with limbs as large as the form allows. Every result must be in that form, and some in the tighter forms that the formulas rely on.
public class P384Field56Test
{
	private const int RandomCount = 32;

	private const ulong Low = 1UL << 56;

	private static readonly BigInteger P = ModulusCase.FromLimbs(P384Field56.Modulus);

	private static readonly BigInteger R = BigInteger.One << 392;

	private static readonly BigInteger RInverse = BigInteger.ModPow(R, P - 2, P);

	// The largest value of the form: every limb at its most.
	private static readonly BigInteger Largest = ValueOf(Limbs(2 * Low - 1, 2 * Low - 1, 2 * Low - 1, 2 * Low - 1, 2 * Low - 1, 2 * Low - 1, (1UL << 50) - 1));

	// What WeakReduce leaves the value below, 2^384 + 2^342, which is below 2p.
	private static readonly BigInteger ReducedBound = (BigInteger.One << 384) + (BigInteger.One << 342);

	private static readonly CurveCase Curve = CurveCase.Named("secp384r1");

	[Test]
	public async Task ArithmeticMatchesBigInteger()
	{
		List<string> failures = [];
		Random random = new(1);

		foreach ((P384Field56 x, P384Field56 y) in Pairs(random))
		{
			BigInteger a = ValueOf(x);
			BigInteger b = ValueOf(y);
			string operands = $"{ShowLimbs(x)}, {ShowLimbs(y)}";
			P384Field56.Multiply(in x, in y, out P384Field56 product);
			CheckProduct(failures, $"Multiply {operands}", product, a, b);
			P384Field56.Square(in x, out product);
			CheckProduct(failures, $"Square {ShowLimbs(x)}", product, a, a);
			P384Field56.Add(in x, in y, out P384Field56 sum);
			CheckReduced(failures, $"Add {operands}", sum, a + b);
			P384Field56.Subtract(in x, in y, out P384Field56 difference);
			CheckReduced(failures, $"Subtract {operands}", difference, a - b);
			P384Field56.Negate(in y, out P384Field56 negated);
			CheckReduced(failures, $"Negate {ShowLimbs(y)}", negated, -b);
			P384Field56.ToMontgomery(in x, out P384Field56 montgomery);
			CheckProduct(failures, $"ToMontgomery {ShowLimbs(x)}", montgomery, a, R * R % P);
			P384Field56.FromMontgomery(in x, out P384Field56 plain);
			CheckProduct(failures, $"FromMontgomery {ShowLimbs(x)}", plain, a, 1);
		}

		await Assert.That(failures).IsEmpty();
	}

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
			foreach (P384Field56 x in Representations(value, random))
			{
				ulong expected = Mod(value).IsZero ? ulong.MaxValue : 0;

				if (P384Field56.IsZero(in x) != expected)
				{
					failures.Add($"IsZero {ShowLimbs(x)}");
				}

				foreach (P384Field56 y in Representations(value, random))
				{
					if (P384Field56.AreEqual(in x, in y) != ulong.MaxValue)
					{
						failures.Add($"AreEqual {ShowLimbs(x)}, {ShowLimbs(y)}");
					}
				}

				foreach (P384Field56 y in Representations(value + 1, random))
				{
					if (P384Field56.AreEqual(in x, in y) is not 0)
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
			foreach (P384Field56 x in Representations(value, random))
			{
				byte[] exported = new byte[48];
				P384Field56.Export(in x, exported);

				if (!exported.AsSpan().SequenceEqual(Curve.EncodeCoordinate(value)))
				{
					failures.Add($"Export {ShowLimbs(x)}");
				}

				// value = aR stands for a, so the inverse a⁻¹R is value⁻¹R²; value^(p − 2) also maps 0 to 0.
				BigInteger inverse = BigInteger.ModPow(value, P - 2, P) * R % P * R % P;
				P384Field56.Invert(in x, out P384Field56 result);
				CheckCanonical(failures, $"Invert {ShowLimbs(x)}", result, inverse);
				P384Field56.InvertVariableTime(in x, out result);
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
			ulong[] limbs = [.. Enumerable.Range(0, 6).Select(i => (ulong)(value >> 64 * i & ulong.MaxValue))];
			P384Field56.FromLimbs(limbs, out P384Field56 element);
			CheckCanonical(failures, $"FromLimbs {value:X}", element, value);

			if (!P384Field56.TryImport(Curve.EncodeCoordinate(value), out element))
			{
				failures.Add($"TryImport {value:X} failed");
			}

			CheckCanonical(failures, $"TryImport {value:X}", element, value);
		}

		foreach (BigInteger value in (BigInteger[])[P, P + 1, (BigInteger.One << 384) - 1])
		{
			if (P384Field56.TryImport(Curve.EncodeCoordinate(value), out P384Field56 element) || ValueOf(element) != 0)
			{
				failures.Add($"TryImport {value:X} accepted or left {ShowLimbs(element)}");
			}
		}

		CheckCanonical(failures, "One", P384Field56.One, R % P);
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
			JacobianPoint<P384Field56> x = Loose(reference.RandomizeJacobian(left, random), random);
			JacobianPoint<P384Field56> y = Loose(reference.RandomizeJacobian(right, random), random);
			P384Field56.Double(in x, out JacobianPoint<P384Field56> twice);
			CheckPoint(failures, reference, $"2 · {Show(left)}", twice, reference.Add(left, left));
			EcGroup<P384Curve, P384Field56, P384Order>.Add(in x, in y, out JacobianPoint<P384Field56> sum);
			CheckPoint(failures, reference, operation, sum, reference.Add(left, right));

			if (right is null)
			{
				continue;
			}

			AffinePoint<P384Field56> affine = Loose(right, random);
			EcGroup<P384Curve, P384Field56, P384Order>.Add(in x, in affine, out sum);
			CheckPoint(failures, reference, $"{operation}, affine", sum, reference.Add(left, right));

			if (left is null)
			{
				continue;
			}

			ulong mask = P384Field56.AddDistinct(in x, in y, out sum);
			CheckDistinct(failures, reference, operation, mask, sum, left, right);
			mask = P384Field56.AddDistinct(in x, in affine, out sum);
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
		AffinePoint<P384Field56> generator = Loose(reference.Generator, random);
		JacobianPoint<P384Field56> point = Loose(reference.RandomizeJacobian(reference.Generator, random), random);
		BigInteger k = 1;
		List<string> failures = [];

		for (int i = 1; i <= 4000 && failures.Count is 0; ++i)
		{
			switch (random.Next(4))
			{
				case 0:
					EcGroup<P384Curve, P384Field56, P384Order>.Add(in point, in generator, out point);
					k += 1;
					break;
				case 1:
					P384Field56.Double(in point, out JacobianPoint<P384Field56> twice);
					EcGroup<P384Curve, P384Field56, P384Order>.Add(in point, in twice, out point);
					k *= 3;
					break;
				default:
					P384Field56.Double(in point, out point);
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
		P384Field56 x = Represent(Largest, AllHigh)!.Value;
		P384Field56 y = Loose(RandomBelow(random, P), random);
		BigInteger a = Mod(ValueOf(x));
		BigInteger b = Mod(ValueOf(y));
		List<string> failures = [];

		for (int i = 0; i < 20000 && failures.Count is 0; ++i)
		{
			switch (random.Next(6))
			{
				case 0:
					P384Field56.Multiply(in x, in y, out x);
					a = a * b * RInverse % P;
					break;
				case 1:
					P384Field56.Square(in x, out x);
					a = a * a * RInverse % P;
					break;
				case 2:
					P384Field56.Add(in x, in y, out x);
					a = (a + b) % P;
					break;
				case 3:
					P384Field56.Subtract(in y, in x, out x);
					a = Mod(b - a);
					break;
				case 4:
					P384Field56.Negate(in x, out x);
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

	private static readonly bool[] AllHigh = [true, true, true, true, true, true];

	private static readonly bool[] AllLow = [false, false, false, false, false, false];

	// Below p, with residues that sit next to the limb boundaries.
	private static IEnumerable<BigInteger> Residues(Random random)
	{
		SortedSet<BigInteger> values = [0, 1, 2, P - 1, P - 2, R % P, R * R % P, (BigInteger.One << 384) - P, Mod(Largest)];

		for (int k = 1; k <= 6; ++k)
		{
			BigInteger power = BigInteger.One << 56 * k;
			values.UnionWith([power - 1, power, power + 1, P - power, P - power + 1]);
		}

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
		}

		values.RemoveWhere(value => value < 0 || value >= P);
		return values;
	}

	private static IEnumerable<(P384Field56 Left, P384Field56 Right)> Pairs(Random random)
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

	// The representations of value + kp in the form, for every k, with limbs 0 to 5 at 2^56 or more where they can be, below 2^56, or either at random.
	private static IEnumerable<P384Field56> Representations(BigInteger value, Random random)
	{
		value = Mod(value);

		for (BigInteger u = value; u <= Largest; u += P)
		{
			bool[] mixed = [.. Enumerable.Range(0, 6).Select(_ => random.Next(2) is 0)];

			foreach (bool[] high in (bool[][])[AllLow, AllHigh, mixed])
			{
				if (Represent(u, high) is { } element)
				{
					yield return element;
				}
			}
		}
	}

	private static P384Field56 Canonical(BigInteger value)
	{
		return Represent(Mod(value), AllLow)!.Value;
	}

	// The representation with the largest value and limbs 0 to 5 at 2^56 or more where they can be.
	private static P384Field56 Highest(BigInteger value)
	{
		BigInteger u = Mod(value);
		u += (Largest - u) / P * P;
		return Represent(u, AllHigh) ?? Represent(u, AllLow)!.Value;
	}

	private static P384Field56 Loose(BigInteger value, Random random)
	{
		P384Field56[] representations = [.. Representations(value, random)];
		return representations[random.Next(representations.Length)];
	}

	// Montgomery coordinates, loose.
	private static JacobianPoint<P384Field56> Loose(JacobianValue value, Random random)
	{
		return new JacobianPoint<P384Field56> { X = Loose(value.X * R, random), Y = Loose(value.Y * R, random), Z = Loose(value.Z * R, random) };
	}

	private static AffinePoint<P384Field56> Loose(CurvePoint point, Random random)
	{
		return new AffinePoint<P384Field56> { X = Loose(point.X * R, random), Y = Loose(point.Y * R, random) };
	}

	// Limbs of u, each of 0 to 5 taking an extra 2^56 from the limb above where high says so and u allows; null if limb 6 does not fit the form.
	private static P384Field56? Represent(BigInteger u, bool[] high)
	{
		ulong[] limbs = new ulong[7];

		for (int i = 0; i < 6; ++i)
		{
			BigInteger limb = u & Low - 1;

			if (high[i] && u >= limb + Low)
			{
				limb += Low;
			}

			limbs[i] = (ulong)limb;
			u = u - limb >> 56;
		}

		if (u >= 1UL << 50)
		{
			return null;
		}

		return Limbs(limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], (ulong)u);
	}

	private static P384Field56 Limbs(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4, ulong l5, ulong l6)
	{
		return new P384Field56 { L0 = l0, L1 = l1, L2 = l2, L3 = l3, L4 = l4, L5 = l5, L6 = l6 };
	}

	// Limbs 0 to 5 as given and limb 6 at the most that keeps the value below 2^392.
	private static P384Field56 Topped(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4, ulong l5)
	{
		BigInteger rest = ValueOf(Limbs(l0, l1, l2, l3, l4, l5, 0));
		return Limbs(l0, l1, l2, l3, l4, l5, (ulong)(R - 1 - rest >> 336));
	}

	private static P384Field56 Same(ulong limb)
	{
		return Limbs(limb, limb, limb, limb, limb, limb, limb);
	}

	private static BigInteger ValueOf(in P384Field56 value)
	{
		return value.L0 + ((BigInteger)value.L1 << 56) + ((BigInteger)value.L2 << 112) + ((BigInteger)value.L3 << 168) + ((BigInteger)value.L4 << 224) + ((BigInteger)value.L5 << 280) + ((BigInteger)value.L6 << 336);
	}

	// The plain coordinates of the Montgomery ones.
	private static JacobianValue Value(in JacobianPoint<P384Field56> point)
	{
		return new JacobianValue(Mod(ValueOf(point.X) * RInverse), Mod(ValueOf(point.Y) * RInverse), Mod(ValueOf(point.Z) * RInverse));
	}

	private static bool IsInForm(in P384Field56 value, ulong low, ulong top)
	{
		return value.L0 < low && value.L1 < low && value.L2 < low && value.L3 < low && value.L4 < low && value.L5 < low && value.L6 < top;
	}

	// Multiply leaves limbs 0 to 5 below 2^56 and the value below x·y/2^392 + p, so limb 6 below 2^48 + 2^45 for inputs of the form.
	private static void CheckProduct(List<string> failures, string operation, in P384Field56 actual, BigInteger x, BigInteger y, bool inForm = true)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(x * y * RInverse) || value * R >= x * y + P * R || !IsInForm(actual, Low, inForm ? (1UL << 48) + (1UL << 45) : ulong.MaxValue))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(x * y * RInverse):X}");
		}
	}

	// WeakReduce leaves limbs 0 to 5 below 2^56 and the value below 2^384 + 2^342.
	private static void CheckReduced(List<string> failures, string operation, in P384Field56 actual, BigInteger expected)
	{
		BigInteger value = ValueOf(actual);

		if (Mod(value) != Mod(expected) || value >= ReducedBound || !IsInForm(actual, Low, (1UL << 48) + (1UL << 6) + 1))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {Mod(expected):X}");
		}
	}

	private static void CheckCanonical(List<string> failures, string operation, in P384Field56 actual, BigInteger expected)
	{
		if (ValueOf(actual) != expected || !IsInForm(actual, Low, 1UL << 48))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {expected:X}");
		}
	}

	private static void CheckPoint(List<string> failures, EcReference reference, string operation, in JacobianPoint<P384Field56> actual, CurvePoint? expected)
	{
		if (!IsInForm(actual.X, 2 * Low, 1UL << 50) || !IsInForm(actual.Y, 2 * Low, 1UL << 50) || !IsInForm(actual.Z, 2 * Low, 1UL << 50))
		{
			failures.Add($"{operation} gave ({ShowLimbs(actual.X)}, {ShowLimbs(actual.Y)}, {ShowLimbs(actual.Z)}), out of the form");
		}

		EcTestUtils.CheckPoint(failures, reference, operation, Value(actual), expected);
	}

	// Equal points give (0, 0, 0) and set the mask; any others give their sum.
	private static void CheckDistinct(List<string> failures, EcReference reference, string operation, ulong mask, in JacobianPoint<P384Field56> actual, CurvePoint left, CurvePoint right)
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

	private static string ShowLimbs(in P384Field56 value)
	{
		return $"[{value.L0:X}, {value.L1:X}, {value.L2:X}, {value.L3:X}, {value.L4:X}, {value.L5:X}, {value.L6:X}]";
	}
}
