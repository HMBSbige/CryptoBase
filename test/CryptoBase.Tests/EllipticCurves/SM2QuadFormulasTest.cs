using CryptoBase.EllipticCurves;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.ECTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

// The rounds of SM2QuadFormulas and SM2OctoFormulas against the reference, and the additions of SM2PairFormulas at the largest differences that they carry, on states and entries at the bounds that SM2QuadFormulas states: a coordinate keeps its value mod p, takes the largest value below its bound by adding multiples of p, and the largest limbs below theirs by borrowing 2^29 from the limb above as often as both limbs allow. Each result must be the reference point, in a state within the same bounds whose δ and α agree with its X and Z.
public class SM2QuadFormulasTest
{
	private const int LimbCount = 9;

	private const int PointCount = 6;

	private const ulong Nominal = 1UL << 29;

	private static readonly CurveCase Curve = CurveCase.Named(CurveCase.SM2Name);

	private static readonly BigInteger P = Curve.Reference.P;

	private static readonly BigInteger R = BigInteger.One << 261;

	private static readonly BigInteger RInverse = BigInteger.ModPow(R, P - 2, P);

	// X of a state below 2p in limbs below 3·2^29 + 2^22, limb 8 below 2^24 + 2^5; Y below 4p in limbs below 2^30, limb 8 below 2^26 + 2; Z below 2.7p in limbs below 2^30 + 2^8; δ a product below 1.25p and α a product below 2.9p.
	private static readonly Bound Abscissa = new(2 * P, [.. Repeat(3 * Nominal + (1UL << 22)).Take(LimbCount - 1), (1UL << 24) + (1UL << 5)]);

	private static readonly Bound Ordinate = new(4 * P, [.. Repeat(2 * Nominal).Take(LimbCount - 1), (1UL << 26) + 2]);

	private static readonly Bound Height = new(27 * P / 10, [.. Repeat(2 * Nominal + (1UL << 8)).Take(LimbCount - 1), (ulong)(27 * P / 10 >> 232) + 1]);

	private static readonly Bound Delta = Product(5 * P / 4);

	private static readonly Bound Alpha = Product(29 * P / 10);

	// X, Y and Z of an entry as Reduce leaves them, and its Z² and Z³ products of such values, limbs 2m and 2m + 1 joined into one ulong and split again.
	private static readonly Bound Reduced = new((BigInteger.One << 256) + (BigInteger.One << 237), [.. Repeat(Nominal).Take(LimbCount - 1), (1UL << 24) + (1UL << 5)]);

	private static readonly Bound Power = Joined(Product(5 * P / 4));

	// The limbs of the 4p of ConditionalNegate.
	private static readonly ulong[] FourP = [SM2Field29.FourP0, SM2Field29.FourP1, SM2Field29.FourP2, SM2Field29.FourP3, SM2Field29.FourPMiddle, SM2Field29.FourPMiddle, SM2Field29.FourPMiddle, SM2Field29.FourP7, SM2Field29.FourP8];

	[Test]
	public async Task QuadRoundsAtTheBoundsMatchTheReference()
	{
		if (!SM2Field29x4Avx2.IsSupported)
		{
			Skip.Test("AVX2 is not supported here.");
		}

		List<string> failures = [];
		Random random = new(21);

		for (int i = 0; i < PointCount; ++i)
		{
			bool extreme = i % 3 is not 0;
			JacobianValue point = RandomJacobian(random);
			JacobianValue other = RandomJacobian(random);
			bool negated = i % 2 is 0;
			CurvePoint entryPoint = Affine(other, negated);
			CurvePoint start = Affine(point, false);
			SM2QuadEntry entry = ToEntry(other, negated, extreme);
			SM2QuadState state = ToState(point, extreme);

			SM2QuadState twice = state;
			SM2QuadFormulas.DoubleTwice(ref twice);
			CheckState(failures, $"DoubleTwice {i}", Lanes(in twice), Curve.Reference.Multiply(start, 4));

			// Each run of a count takes the state that the run before left, within the same bounds, on the same scratch.
			SM2QuadState repeated = state;
			SM2QuadFormulas.DoubleTwice(ref repeated, 3);
			CheckState(failures, $"DoubleTwice 3 times {i}", Lanes(in repeated), Curve.Reference.Multiply(start, 64));

			SM2QuadState once = state;
			SM2QuadFormulas.DoubleOnce(ref once);
			CheckState(failures, $"DoubleOnce {i}", Lanes(in once), Curve.Reference.Multiply(start, 2));

			SM2QuadState sum = state;
			SM2QuadFormulas.AddState(ref sum, in entry);
			CheckState(failures, $"AddState {i}", Lanes(in sum), Curve.Reference.Add(start, entryPoint));

			SM2QuadFormulas.FromEntry(in entry, out SM2QuadState fromEntry);
			CheckState(failures, $"FromEntry {i}", Lanes(in fromEntry), entryPoint);

			// The masks of DoubleAdd: the sum, the double for a digit of 0, and the entry for the point at infinity.
			foreach ((ulong zero, ulong infinity, CurvePoint? expected) in (ReadOnlySpan<(ulong, ulong, CurvePoint?)>)[(0, 0, Curve.Reference.Add(Curve.Reference.Multiply(start, 2), entryPoint)), (ulong.MaxValue, 0, Curve.Reference.Multiply(start, 2)), (0, ulong.MaxValue, entryPoint)])
			{
				ulong[] masks = [zero, zero, zero, zero, infinity, infinity, infinity, infinity];
				SM2QuadState doubled = state;
				SM2QuadFormulas.DoubleAdd(ref doubled, in entry, in masks[0], in masks[4]);
				CheckState(failures, $"DoubleAdd {i}, zero {zero:X}, infinity {infinity:X}", Lanes(in doubled), expected);
			}

			SM2QuadFormulas.ToJacobian(in state, out JacobianPoint<SM2Field52> jacobian);
			CheckPoint(failures, Curve.Reference, $"ToJacobian {i}", ToValue(in jacobian), start);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Each half of the eight lanes holds a state and an entry of its own.
	[Test]
	public async Task OctoRoundsAtTheBoundsMatchTheReference()
	{
		if (!SM2Field29x8Avx512.IsSupported)
		{
			Skip.Test("AVX-512 is not supported here.");
		}

		List<string> failures = [];
		Random random = new(22);

		for (int i = 0; i < PointCount; ++i)
		{
			JacobianValue[] points = [RandomJacobian(random), RandomJacobian(random)];
			JacobianValue[] others = [RandomJacobian(random), RandomJacobian(random)];
			bool[] negated = [i % 2 is 0, i % 2 is 1];
			SM2OctoState state = default;
			SM2OctoEntry entry = default;

			for (int half = 0; half < 2; ++half)
			{
				bool extreme = (i + half) % 3 is not 0;
				SetHalf(ref state, half, ToState(points[half], extreme));
				SetHalf(ref entry, half, ToEntry(others[half], negated[half], extreme));
			}

			SM2OctoState twice = state;
			SM2OctoFormulas.DoubleTwice(ref twice);
			SM2OctoFormulas.FromEntry(in entry, out SM2OctoState fromEntry);
			SM2OctoState doubled = state;
			SM2OctoFormulas.DoubleAdd(ref doubled, in entry);

			for (int half = 0; half < 2; ++half)
			{
				CurvePoint start = Affine(points[half], false);
				CurvePoint entryPoint = Affine(others[half], negated[half]);
				CurvePoint? sum = Curve.Reference.Add(Curve.Reference.Multiply(start, 2), entryPoint);
				CheckState(failures, $"DoubleTwice {i}, half {half}", Lanes(in twice, half), Curve.Reference.Multiply(start, 4));
				CheckState(failures, $"FromEntry {i}, half {half}", Lanes(in fromEntry, half), entryPoint);
				CheckState(failures, $"DoubleAdd {i}, half {half}", Lanes(in doubled, half), sum);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task QuadTableMatchesTheReference()
	{
		if (!SM2Field29x4Avx2.IsSupported)
		{
			Skip.Test("AVX2 is not supported here.");
		}

		await Assert.That(CheckTable(SM2QuadFormulas.BuildTable, static j => j + 1)).IsEmpty();
	}

	[Test]
	public async Task OctoTableMatchesTheReference()
	{
		if (!SM2Field29x8Avx512.IsSupported)
		{
			Skip.Test("AVX-512 is not supported here.");
		}

		await Assert.That(CheckTable(SM2OctoFormulas.BuildTable, static j => 2 * j + 1)).IsEmpty();
	}

	// Each table of BuildTables, with a random point in the other half.
	[Test]
	public async Task OctoTablesMatchTheReference()
	{
		if (!SM2Field29x8Avx512.IsSupported)
		{
			Skip.Test("AVX-512 is not supported here.");
		}

		CurvePoint point = Curve.Reference.RandomPoint(new Random(24));
		AffinePoint<SM2Field52> other = new() { X = ToElement(point.X), Y = ToElement(point.Y) };
		ulong[] otherTable = new ulong[16 * 25];

		using (Assert.Multiple())
		{
			await Assert.That(CheckTable((in first, table) => SM2OctoFormulas.BuildTables(in first, in other, table, otherTable), static j => 2 * j + 1)).IsEmpty();
			await Assert.That(CheckTable((in second, table) => SM2OctoFormulas.BuildTables(in other, in second, otherTable, table), static j => 2 * j + 1)).IsEmpty();
		}
	}

	private delegate void TableBuilder(in AffinePoint<SM2Field52> point, Span<ulong> table);

	// The entries in the layout of SM2PairFormulas: X, Y and Z as Reduce leaves them, then Z² and Z³ of Z, limbs 2m and 2m + 1 joined into one ulong.
	private static List<string> CheckTable(TableBuilder build, Func<int, int> multiple)
	{
		List<string> failures = [];
		Random random = new(23);

		for (int i = 0; i < 2; ++i)
		{
			CurvePoint point = Curve.Reference.RandomPoint(random);
			AffinePoint<SM2Field52> affine = new() { X = ToElement(point.X), Y = ToElement(point.Y) };
			ulong[] table = new ulong[16 * 25];
			build(in affine, table);

			for (int j = 0; j < 16; ++j)
			{
				ulong[] entry = table[(j * 25)..((j + 1) * 25)];
				ulong[] x = SplitJoined([.. Enumerable.Range(0, 5).Select(k => entry[2 * k])]);
				ulong[] y = SplitJoined([.. Enumerable.Range(0, 5).Select(k => entry[2 * k + 1])]);
				ulong[] cube = SplitJoined([.. Enumerable.Range(0, 5).Select(k => entry[10 + 2 * k])]);
				ulong[] z = SplitJoined([.. Enumerable.Range(0, 5).Select(k => entry[11 + 2 * k])]);
				ulong[] square = SplitJoined(entry[20..]);
				string operation = $"Entry {j} of table {i}";
				CheckPoint(failures, Curve.Reference, operation, new JacobianValue(Plain(x), Plain(y), Plain(z)), Curve.Reference.Multiply(point, multiple(j)));
				CheckBound(failures, $"{operation} X", x, Reduced);
				CheckBound(failures, $"{operation} Y", y, Reduced);
				CheckBound(failures, $"{operation} Z", z, Reduced);
				CheckBound(failures, $"{operation} Z²", square, Power);
				CheckBound(failures, $"{operation} Z³", cube, Power);

				if (Plain(square) != Plain(z) * Plain(z) % P || Plain(cube) != Plain(square) * Plain(z) % P)
				{
					failures.Add($"{operation} has Z² or Z³ of another Z");
				}
			}
		}

		return failures;
	}

	// The additions of SM2PairFormulas take H = U2 − U1 + 4p, limb by limb, into H·H once carried. Its limbs come nearest 3·2^29 where the limbs of the product U2 are largest and those of U1 smallest, which the inputs steer to: residues u and v with limbs 0 to 7 of 2^20, whose products Multiply gives without the borrows that limbs of 0 would take, or of 2^29 − 1, and limb 8 of 2^23, above every multiple of p that a product may add; x2/x1 = v/u, and λ with x1·λ²·R = u gives U1 = u and U2 = v for Z1·Z2 = λ in Add and Z1 = λ in AddAffine. Add takes R = S2 − S1 + 4p into R·R the same way, for S1 = Y1·Z2³ and S2 = Y2·Z1³, which y2/y1 = v/u and λ with y1·λ³·R = u steer to in a case of their own. Uncarried, column 7 of H·H or R·R would then exceed 2^64, which each case checks before it adds.
	[Test]
	public async Task PairAdditionsAtTheLargestDifferencesMatchTheReference()
	{
		List<string> failures = [];

		if (SM2Field29x2.IsSupported)
		{
			CheckPairAdditions<SM2Field29x2>(failures);
		}
		else
		{
			Skip.Test("Neither SSE4.1 nor AdvSimd is supported here.");
		}

		await Assert.That(failures).IsEmpty();
	}

	// The rounds cannot steer their products to the limbs at which a fold matters most, so this test checks the arithmetic of the bound: FourPFold2 and FourPFold3 keep the value of 4p, and limb 2 of a + 4p − b for products a and b, at least FourPFold2 minus the largest limb of a product, stays non-negative once a fold takes h·2^6 from it for the h = L8 >> 24 of a value below 7.2p, the largest that the rounds fold.
	[Test]
	public async Task FoldsKeepLimb2NonNegative()
	{
		ulong[] fold = [SM2Field29.FourP0, SM2Field29.FourP1, SM2Field29.FourPFold2, SM2Field29.FourPFold3, .. Enumerable.Repeat(SM2Field29.FourPMiddle, 3), SM2Field29.FourP7, SM2Field29.FourP8];
		BigInteger h = 72 * P / 10 >> 256;
		BigInteger lowest = SM2Field29.FourPFold2 - (Nominal + 64) - (h << 6);

		await Assert.That(ValueOf(fold)).IsEqualTo(4 * P);
		await Assert.That(lowest >= 0).IsTrue();
	}

	private static void CheckPairAdditions<TField>(List<string> failures) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		Random random = new(24);
		BigInteger u = Enumerable.Range(0, LimbCount - 1).Aggregate(BigInteger.One << 255, static (sum, k) => sum + (BigInteger.One << 20 + 29 * k));
		BigInteger v = (BigInteger.One << 255) + (BigInteger.One << 232) - 1;

		for (int i = 0; i < PointCount; ++i)
		{
			(CurvePoint first, CurvePoint second, BigInteger lambda) = ExtremePoints(random, u, v);
			CurvePoint? expected = Curve.Reference.Add(first, second);
			BigInteger z1 = ECReference.RandomBelow(random, P - 1) + 1;
			BigInteger z2 = lambda * Curve.Reference.Inverse(z1) % P;

			// Add: U1 = X1·Z2² and U2 = X2·Z1².
			SM2PairPoint<TField> point = PairPoint<TField>(first, z1);
			SM2PairEntry<TField> entry = PairEntry<TField>(second, z2);
			BigInteger x2 = second.X * z2 % P * z2 % P;
			ulong[] u1 = MultiplyLane<TField>(Montgomery(first.X * z1 % P * z1), Montgomery(z2 * z2));
			ulong[] u2 = MultiplyLane<TField>(Montgomery(x2), MultiplyLane<TField>(Montgomery(z1), Montgomery(z1)));
			CheckOverflow(failures, $"Add {i}", u2, u1);
			SM2PairFormulas<TField>.Add(in point, in entry, out SM2PairPoint<TField> sum);
			CheckPairPoint(failures, $"Add {i}", in sum, expected);

			// AddAffine: U1 = X1 and U2 = x2·Z1².
			SM2PairPoint<TField> affinePoint = PairPoint<TField>(first, lambda);
			TField affine = Lanes<TField>(Montgomery(second.X), Montgomery(second.Y));
			u2 = MultiplyLane<TField>(Montgomery(second.X), MultiplyLane<TField>(Montgomery(lambda), Montgomery(lambda)));
			CheckOverflow(failures, $"AddAffine {i}", u2, Montgomery(first.X * lambda % P * lambda));
			SM2PairFormulas<TField>.AddAffine(ref affinePoint, in affine);
			CheckPairPoint(failures, $"AddAffine {i}", in affinePoint, expected);

			// Add: S1 = Y1·Z2³ and S2 = (Y2·Z1)·Z1².
			(first, second, lambda) = ExtremeOrdinates(random, u, v);
			expected = Curve.Reference.Add(first, second);
			z1 = ECReference.RandomBelow(random, P - 1) + 1;
			z2 = lambda * Curve.Reference.Inverse(z1) % P;
			point = PairPoint<TField>(first, z1);
			entry = PairEntry<TField>(second, z2);
			BigInteger y2 = second.Y * z2 % P * z2 % P * z2 % P;
			ulong[] s1 = MultiplyLane<TField>(Montgomery(first.Y * z1 % P * z1 % P * z1), Montgomery(z2 * z2 % P * z2));
			ulong[] s2 = MultiplyLane<TField>(MultiplyLane<TField>(Montgomery(y2), Montgomery(z1)), MultiplyLane<TField>(Montgomery(z1), Montgomery(z1)));
			CheckOverflow(failures, $"Add of extreme R {i}", s2, s1);
			SM2PairFormulas<TField>.Add(in point, in entry, out sum);
			CheckPairPoint(failures, $"Add of extreme R {i}", in sum, expected);
		}
	}

	// Points P1 and P2 on the curve with x2/x1 = v/u and λ with x1·λ²·R = u, for P1 random.
	private static (CurvePoint First, CurvePoint Second, BigInteger Lambda) ExtremePoints(Random random, BigInteger u, BigInteger v)
	{
		BigInteger ratio = v * Curve.Reference.Inverse(u) % P;

		while (true)
		{
			CurvePoint first = Curve.Reference.RandomPoint(random);
			CurvePoint second = Curve.Reference.PointWithXFrom(first.X * ratio % P);

			if (second.X == first.X * ratio % P && Curve.Reference.SquareRoot(u * Curve.Reference.Inverse(first.X * R) % P) is { } lambda)
			{
				return (first, second, lambda);
			}
		}
	}

	// Points P1 and P2 on the curve with y2/y1 = v/u and λ with y1·λ³·R = u, for P1 random and P2 the one point of its y-coordinate; p ≡ 2 (mod 3), so every residue has the one cube root w^((2p − 1)/3).
	private static (CurvePoint First, CurvePoint Second, BigInteger Lambda) ExtremeOrdinates(Random random, BigInteger u, BigInteger v)
	{
		BigInteger ratio = v * Curve.Reference.Inverse(u) % P;

		while (true)
		{
			CurvePoint first = Curve.Reference.RandomPoint(random);

			if (Curve.Reference.PointWithY(first.Y * ratio % P) is { } second)
			{
				BigInteger cube = u * Curve.Reference.Inverse(first.Y * R) % P;
				return (first, second, BigInteger.ModPow(cube, (2 * P - 1) / 3, P));
			}
		}
	}

	// The point (x·z², y·z³, z) of an affine point, in Montgomery form and canonical limbs, as Reduce leaves them.
	private static SM2PairPoint<TField> PairPoint<TField>(CurvePoint point, BigInteger z) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		BigInteger square = z * z % P;
		ulong[] x = Montgomery(point.X * square);
		return new SM2PairPoint<TField> { XX = Lanes<TField>(x, x), YZ = Lanes<TField>(Montgomery(point.Y * square % P * z), Montgomery(z)) };
	}

	// The entry [X | Y], [Z³ | Z] and [Z² | 0] of the point (x·z², y·z³, z), as PairPoint gives its coordinates.
	private static SM2PairEntry<TField> PairEntry<TField>(CurvePoint point, BigInteger z) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		BigInteger square = z * z % P;
		BigInteger cube = square * z % P;
		return new SM2PairEntry<TField> { XY = Lanes<TField>(Montgomery(point.X * square), Montgomery(point.Y * cube)), CubeZ = Lanes<TField>(Montgomery(cube), Montgomery(z)), SquareZ = Lanes<TField>(Montgomery(square), new ulong[LimbCount]) };
	}

	// A value of two lanes from the limbs of each.
	private static TField Lanes<TField>(ulong[] low, ulong[] high) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		TField value = default;
		SetLane(ref value, 0, low);
		SetLane(ref value, 1, high);
		return value;
	}

	// Uncarried, H = U2 + 4p − U1 limb by limb would take column 7 of H·H above 2^64.
	private static void CheckOverflow(List<string> failures, string operation, ulong[] minuend, ulong[] subtrahend)
	{
		BigInteger[] difference = [.. Enumerable.Range(0, LimbCount).Select(k => (BigInteger)minuend[k] + FourP[k] - subtrahend[k])];
		BigInteger column = Enumerable.Range(0, 8).Aggregate(BigInteger.Zero, (sum, k) => sum + difference[k] * difference[7 - k]);

		if (column < BigInteger.One << 64)
		{
			failures.Add($"{operation} does not reach the differences it is to test: column 7 is {column:X}");
		}
	}

	// X in lane 0 of XX and Y and Z in YZ must hold the expected point, each as Reduce leaves it.
	private static void CheckPairPoint<TField>(List<string> failures, string operation, in SM2PairPoint<TField> point, CurvePoint? expected) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		ulong[] x = GetLane(in point.XX, 0);
		ulong[] y = GetLane(in point.YZ, 0);
		ulong[] z = GetLane(in point.YZ, 1);
		CheckPoint(failures, Curve.Reference, operation, new JacobianValue(Plain(x), Plain(y), Plain(z)), expected);
		CheckBound(failures, $"{operation} X", x, Reduced);
		CheckBound(failures, $"{operation} Y", y, Reduced);
		CheckBound(failures, $"{operation} Z", z, Reduced);
	}

	// Lane 0 of the product of two values given by their limbs.
	private static ulong[] MultiplyLane<TField>(ulong[] left, ulong[] right) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		TField x = default;
		TField y = default;
		SetLane(ref x, 0, left);
		SetLane(ref y, 0, right);
		TField.Multiply(in x, in y, out TField product);
		return GetLane(in product, 0);
	}

	// The canonical limbs of the Montgomery form of a plain value.
	private static ulong[] Montgomery(BigInteger plain)
	{
		return Split(plain * R % P);
	}

	private sealed record Bound(BigInteger Value, ulong[] Limbs);

	private static Bound Product(BigInteger value)
	{
		return new Bound(value, [Nominal, Nominal, .. Repeat(Nominal + 65).Take(6), (ulong)(value - 1 >> 232) + 1]);
	}

	// Joining limbs 2m and 2m + 1 into one ulong and splitting again adds at most 1 to limbs 1, 3, 5 and 7.
	private static Bound Joined(Bound bound)
	{
		return new Bound(bound.Value, [.. bound.Limbs.Select(static (limb, i) => i % 2 is 1 ? limb + 1 : limb)]);
	}

	private static ulong[] Repeat(ulong limb)
	{
		return [.. Enumerable.Repeat(limb, LimbCount)];
	}

	private static JacobianValue RandomJacobian(Random random)
	{
		return Curve.Reference.RandomizeJacobian(Curve.Reference.RandomPoint(random), random);
	}

	private static CurvePoint Affine(JacobianValue value, bool negated)
	{
		CurvePoint point = Curve.Reference.ToAffine(value) ?? throw new InvalidOperationException("The point is the point at infinity.");
		return negated ? Curve.Reference.Negate(point) ?? throw new InvalidOperationException("The point is the point at infinity.") : point;
	}

	// A state P = [α, Y, X, Z] and Q = [X, δ, ·, α] of the point at its bounds or in canonical limbs.
	private static SM2QuadState ToState(JacobianValue value, bool extreme)
	{
		BigInteger square = value.Z * value.Z % P;
		ulong[] alpha = Represent(Curve.Reference.Mod(3 * (value.X - square) * (value.X + square)), Alpha, extreme);
		ulong[] x = Represent(value.X, Abscissa, extreme);
		SM2QuadState state = default;
		SetLane(ref state.P, 0, alpha);
		SetLane(ref state.P, 1, Represent(value.Y, Ordinate, extreme));
		SetLane(ref state.P, 2, x);
		SetLane(ref state.P, 3, Represent(value.Z, Height, extreme));
		SetLane(ref state.Q, 0, x);
		SetLane(ref state.Q, 1, Represent(square, Delta, extreme));
		SetLane(ref state.Q, 3, alpha);
		return state;
	}

	// An entry EA = [Z², X, Y, Z] and EB = [X, Z², Z³, Z³] of the point, with Y negated as ConditionalNegate does it.
	private static SM2QuadEntry ToEntry(JacobianValue value, bool negated, bool extreme)
	{
		BigInteger square = value.Z * value.Z % P;
		ulong[] x = Represent(value.X, Reduced, extreme);
		ulong[] y = Represent(value.Y, Reduced, extreme);
		ulong[] z = Represent(value.Z, Reduced, extreme);
		ulong[] squares = Represent(square, Power, extreme);
		ulong[] cubes = Represent(square * value.Z % P, Power, extreme);

		if (negated)
		{
			y = [.. FourP.Zip(y, static (four, limb) => four - limb)];
		}

		SM2QuadEntry entry = default;
		SetLane(ref entry.EA, 0, squares);
		SetLane(ref entry.EA, 1, x);
		SetLane(ref entry.EA, 2, y);
		SetLane(ref entry.EA, 3, z);
		SetLane(ref entry.EB, 0, x);
		SetLane(ref entry.EB, 1, squares);
		SetLane(ref entry.EB, 2, cubes);
		SetLane(ref entry.EB, 3, cubes);
		return entry;
	}

	// The Montgomery form of a plain value, at its bound or in canonical limbs.
	private static ulong[] Represent(BigInteger plain, Bound bound, bool extreme)
	{
		BigInteger residue = plain * R % P;
		return extreme ? Extreme(residue, bound) : Split(residue);
	}

	// The largest value of the residue below the bound, with each limb below 8 raised by 2^29 as often as its bound and the limb above allow.
	private static ulong[] Extreme(BigInteger residue, Bound bound)
	{
		ulong[] limbs = Split(residue + (bound.Value - 1 - residue) / P * P);

		for (int i = 0; i < LimbCount - 1; ++i)
		{
			ulong borrow = Math.Min(bound.Limbs[i] - 1 - limbs[i] >> 29, limbs[i + 1]);
			limbs[i] += borrow << 29;
			limbs[i + 1] -= borrow;
		}

		return limbs;
	}

	private static ulong[] Split(BigInteger value)
	{
		ulong[] limbs = new ulong[LimbCount];

		for (int i = 0; i < LimbCount; ++i)
		{
			limbs[i] = (ulong)(i < LimbCount - 1 ? value >> 29 * i & Nominal - 1 : value >> 29 * i);
		}

		return limbs;
	}

	// Limbs 0 to 7 from the four ulongs that join them in pairs, and limb 8 from the fifth.
	private static ulong[] SplitJoined(ulong[] joined)
	{
		return [.. joined.Take(4).SelectMany(static limb => (ulong[])[limb & Nominal - 1, limb >> 29]), joined[4]];
	}

	private static BigInteger ValueOf(ulong[] limbs)
	{
		BigInteger value = 0;

		for (int i = LimbCount - 1; i >= 0; --i)
		{
			value = (value << 29) + limbs[i];
		}

		return value;
	}

	// The plain value of limbs in Montgomery form.
	private static BigInteger Plain(ulong[] limbs)
	{
		return ValueOf(limbs) % P * RInverse % P;
	}

	private static void SetLane<TField>(ref TField value, int lane, ulong[] limbs) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		Span<ulong> span = MemoryMarshal.Cast<TField, ulong>(new Span<TField>(ref value));

		for (int limb = 0; limb < LimbCount; ++limb)
		{
			span[limb * TField.LaneCount + lane] = limbs[limb];
		}
	}

	private static ulong[] GetLane<TField>(in TField value, int lane) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		ReadOnlySpan<ulong> span = MemoryMarshal.Cast<TField, ulong>(new ReadOnlySpan<TField>(in value));
		ulong[] limbs = new ulong[LimbCount];

		for (int limb = 0; limb < LimbCount; ++limb)
		{
			limbs[limb] = span[limb * TField.LaneCount + lane];
		}

		return limbs;
	}

	private static void SetHalf(ref SM2OctoState state, int half, SM2QuadState value)
	{
		for (int lane = 0; lane < 4; ++lane)
		{
			SetLane(ref state.P, 4 * half + lane, GetLane(in value.P, lane));
			SetLane(ref state.Q, 4 * half + lane, GetLane(in value.Q, lane));
		}
	}

	private static void SetHalf(ref SM2OctoEntry entry, int half, SM2QuadEntry value)
	{
		for (int lane = 0; lane < 4; ++lane)
		{
			SetLane(ref entry.EA, 4 * half + lane, GetLane(in value.EA, lane));
			SetLane(ref entry.EB, 4 * half + lane, GetLane(in value.EB, lane));
		}
	}

	private static ulong[][] Lanes(in SM2QuadState state)
	{
		return [GetLane(in state.P, 0), GetLane(in state.P, 1), GetLane(in state.P, 2), GetLane(in state.P, 3), GetLane(in state.Q, 0), GetLane(in state.Q, 1), GetLane(in state.Q, 3)];
	}

	private static ulong[][] Lanes(in SM2OctoState state, int half)
	{
		int offset = 4 * half;
		return [GetLane(in state.P, offset), GetLane(in state.P, offset + 1), GetLane(in state.P, offset + 2), GetLane(in state.P, offset + 3), GetLane(in state.Q, offset), GetLane(in state.Q, offset + 1), GetLane(in state.Q, offset + 3)];
	}

	// The lanes [α, Y, X, Z] of P and [X, δ, α] of Q must hold the expected point within the bounds of a state, with δ = Z², α = 3(X − δ)(X + δ) and the copies in Q those of P.
	private static void CheckState(List<string> failures, string operation, ulong[][] lanes, CurvePoint? expected)
	{
		(ulong[] alpha, ulong[] y, ulong[] x, ulong[] z, ulong[] qx, ulong[] delta, ulong[] qAlpha) = (lanes[0], lanes[1], lanes[2], lanes[3], lanes[4], lanes[5], lanes[6]);
		CheckPoint(failures, Curve.Reference, operation, new JacobianValue(Plain(x), Plain(y), Plain(z)), expected);
		CheckBound(failures, $"{operation} α", alpha, Alpha);
		CheckBound(failures, $"{operation} Y", y, Ordinate);
		CheckBound(failures, $"{operation} X", x, Abscissa);
		CheckBound(failures, $"{operation} Z", z, Height);
		CheckBound(failures, $"{operation} δ", delta, Delta);
		BigInteger plainDelta = Plain(delta);
		BigInteger plainX = Plain(x);

		if (plainDelta != Plain(z) * Plain(z) % P || Plain(alpha) != Curve.Reference.Mod(3 * (plainX - plainDelta) * (plainX + plainDelta)) || Plain(qx) != plainX || Plain(qAlpha) != Plain(alpha))
		{
			failures.Add($"{operation} gave δ or α of another point");
		}
	}

	private static void CheckBound(List<string> failures, string operation, ulong[] limbs, Bound bound)
	{
		if (ValueOf(limbs) >= bound.Value || limbs.Zip(bound.Limbs).Any(static pair => pair.First >= pair.Second))
		{
			failures.Add($"{operation} is out of bounds: {string.Join(":", limbs.Select(static limb => limb.ToString("X")))}");
		}
	}

	private static SM2Field52 ToElement(BigInteger value)
	{
		if (!SM2Field52.TryImport(CurveCase.EncodeInteger(value, SM2Field52.ByteLength), out SM2Field52 element))
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, "The value is not below p.");
		}

		SM2Field52.ToMontgomery(in element, out element);
		return element;
	}

	private static JacobianValue ToValue(in JacobianPoint<SM2Field52> point)
	{
		return new JacobianValue(FieldValue(in point.X), FieldValue(in point.Y), FieldValue(in point.Z));
	}

	private static BigInteger FieldValue(in SM2Field52 element)
	{
		SM2Field52.FromMontgomery(in element, out SM2Field52 plain);
		byte[] bytes = new byte[SM2Field52.ByteLength];
		SM2Field52.Export(in plain, bytes);
		return ModulusCase.Decode(bytes);
	}
}
