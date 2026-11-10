using CryptoBase.EllipticCurves;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.ECTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class SM2KernelTest
{
	private const int RandomCount = 16;

	private const int OddWidth = SM2OddWindows.Width;

	// The k at which the chains of SM2OctoFormulas would meet equal points for s below n, the exception of SM2OddWindows.
	private static readonly BigInteger SplitException = BigInteger.Parse("075C742E8DF5349B13D0069914C6FDA21A", System.Globalization.NumberStyles.HexNumber);

	// The width of the windows of k·G for secret scalars, 6.
	private static readonly int WindowWidth = SM2Curve.GeneratorWindowWidth;

	private static readonly CurveCase Curve = CurveCase.Named(CurveCase.SM2Name);

	private static readonly Lazy<(BigInteger Scalar, CurvePoint? Product)[]> BaseProducts = new(ComputeBaseProducts);

	private static readonly Lazy<(CurvePoint Point, (BigInteger Scalar, CurvePoint? Product)[] Products)[]> PointProducts = new(ComputePointProducts);

	// The scalars of Scalars for the windows of 8 bits of SM2VerificationCurve, which the products of public scalars take.
	private static readonly Lazy<BigInteger[]> VerificationScalars = new(static () => [.. Scalars(SM2VerificationCurve.GeneratorWindowWidth)]);

	// Random points P with their tables and k·P for the scalars of MultiplyBaseMatchesTheReference, as the windows of a table of P split into blocks as those of G do.
	private static readonly Lazy<(CurvePoint Point, ECPointTable<SM2Curve, SM2Field52, SM2Order> Table, (BigInteger Scalar, CurvePoint? Product)[] Products)[]> FixedProducts = new(ComputeFixedProducts);

	// The inputs of the tests of u1·G + u2·Q with their reference sums, which every kernel shares.
	private static readonly Lazy<(AffinePoint<SM2Field52>[] Table, Sum[] Sums)> TableSums = new(ComputeTableSums);

	private static readonly Lazy<(ECPointTable<SM2VerificationCurve, SM2Field52, SM2Order> Table, Sum[] Sums)> FixedSums = new(ComputeFixedSums);

	private static readonly Lazy<(AffinePoint<SM2Field52> Point, Sum[] Sums)> PointSums = new(ComputePointSums);

	private readonly record struct Sum(BigInteger U1, BigInteger U2, CurvePoint? Expected);

	// What the reference gives for the tables of TCurve, once for all the kernels.
	private static class TableMultiples<TCurve> where TCurve : struct, IECCurve
	{
		// ReSharper disable once StaticMemberInGenericType
		internal static readonly Lazy<(CurvePoint Point, CurvePoint?[] Bases)[]> Bases = new(ComputeBases);

		// (j + 1)·2^(wi)·P at entry i·L + j of the windows, for the table of the first point of FixedProducts.
		internal static readonly Lazy<(ECPointTable<TCurve, SM2Field52, SM2Order> Table, CurvePoint?[] Entries)> Entries = new(ComputeEntries);

		private static (CurvePoint, CurvePoint?[])[] ComputeBases()
		{
			BigInteger[] powers = [.. Enumerable.Range(0, ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowCount).Select(static i => BigInteger.One << i * TCurve.GeneratorWindowWidth)];
			return [.. PointProducts.Value.Select(entry => (entry.Point, Curve.Reference.Multiply(entry.Point, powers)))];
		}

		private static (ECPointTable<TCurve, SM2Field52, SM2Order>, CurvePoint?[]) ComputeEntries()
		{
			CurvePoint point = FixedProducts.Value[0].Point;
			int windowCount = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowCount;
			int windowLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowLength;
			CurvePoint?[] entries = new CurvePoint?[windowCount * windowLength];
			CurvePoint? windowBase = point;

			for (int i = 0; i < windowCount; ++i)
			{
				CurvePoint? multiple = null;

				for (int j = 0; j < windowLength; ++j)
				{
					multiple = Curve.Reference.Add(multiple, windowBase);
					entries[i * windowLength + j] = multiple;
				}

				for (int k = 0; k < TCurve.GeneratorWindowWidth; ++k)
				{
					windowBase = Curve.Reference.Add(windowBase, windowBase);
				}
			}

			return (new ECPointTable<TCurve, SM2Field52, SM2Order>(ToPoint(point)), entries);
		}
	}

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(SM2KernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(ISM2Kernel)));
	}

	// Every result must also be in the form E of SM2Field52, which the callers of ECGroup.MultiplyBase take.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task MultiplyBaseMatchesTheReference(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in BaseProducts.Value)
		{
			kernel.MultiplyBase(ToScalar(scalar), out JacobianPoint<SM2Field52> product);

			if (!IsOfFormE(in product.X) || !IsOfFormE(in product.Y) || !IsOfFormE(in product.Z))
			{
				failures.Add($"{scalar:X} · G gave limbs outside the form E");
				continue;
			}

			CheckPoint(failures, Curve.Reference, $"{scalar:X} · G", ToValue(in product), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Each kernel sets base i of the windows of a table to 2^(wi)·P, in the form E, as the reference doubles P, for G and a random point, with the windows of 6 bits of SM2Curve and those of 8 of SM2VerificationCurve.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task FillBasesDoublesThePoint(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		CheckFillBases<SM2Curve>(kernel, failures);
		CheckFillBases<SM2VerificationCurve>(kernel, failures);
		await Assert.That(failures).IsEmpty();
	}

	// Each kernel fills the windows of a table from their bases alone: entry j of window i is (j + 1)·2^(wi)·P, as the reference adds them up, for the windows of both curves.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task FillWindowsHoldsTheMultiples(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		CheckFillWindows<SM2Curve>(kernel, failures);
		CheckFillWindows<SM2VerificationCurve>(kernel, failures);
		await Assert.That(failures).IsEmpty();
	}

	private static void CheckFillBases<TCurve>(SM2KernelCase kernel, List<string> failures) where TCurve : struct, IECCurve
	{
		int windowCount = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowCount;

		foreach ((CurvePoint point, CurvePoint?[] expected) in TableMultiples<TCurve>.Bases.Value)
		{
			JacobianPoint<SM2Field52>[] bases = new JacobianPoint<SM2Field52>[windowCount];
			kernel.FillBases<TCurve>(ToPoint(point), bases);

			for (int i = 0; i < windowCount; ++i)
			{
				if (!IsOfFormE(in bases[i].X) || !IsOfFormE(in bases[i].Y) || !IsOfFormE(in bases[i].Z))
				{
					failures.Add($"base {i} of ({point.X:X}, …) for {typeof(TCurve).Name} has limbs outside the form E");
				}

				CheckPoint(failures, Curve.Reference, $"base {i} of ({point.X:X}, …) for {typeof(TCurve).Name}", ToValue(in bases[i]), expected[i]);
			}
		}
	}

	private static void CheckFillWindows<TCurve>(SM2KernelCase kernel, List<string> failures) where TCurve : struct, IECCurve
	{
		(ECPointTable<TCurve, SM2Field52, SM2Order> table, CurvePoint?[] expected) = TableMultiples<TCurve>.Entries.Value;
		int windowCount = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowCount;
		int windowLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.WindowLength;
		int entryLength = ECGeneratorTable<TCurve, SM2Field52, SM2Order>.EntryLength;
		ulong[] windows = new ulong[table.Windows.Length];

		for (int i = 0; i < windowCount; ++i)
		{
			table.Windows.Slice(i * windowLength * entryLength, entryLength).CopyTo(windows.AsSpan(i * windowLength * entryLength));
		}

		kernel.FillWindows<TCurve>(windows);

		for (int e = 0; e < expected.Length; ++e)
		{
			ECGeneratorTable<TCurve, SM2Field52, SM2Order>.Read(windows, e, out AffinePoint<SM2Field52> entry);

			if (new CurvePoint(FieldValue(in entry.X), FieldValue(in entry.Y)) != expected[e])
			{
				failures.Add($"window {e / windowLength}, entry {e % windowLength} for {typeof(TCurve).Name}");
			}
		}
	}

	// The windows of the table of P split into blocks as those of G do, so the scalars around the splits of MultiplyBaseMatchesTheReference serve for both products, each of which must match its reference; k·P must also match what Multiply gives without the table.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task MultiplyBaseAndFixedMatchesTheReference(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];

		foreach ((CurvePoint point, ECPointTable<SM2Curve, SM2Field52, SM2Order> table, (BigInteger Scalar, CurvePoint? Product)[] products) in FixedProducts.Value)
		{
			AffinePoint<SM2Field52> affine = ToPoint(point);

			foreach (((BigInteger scalar, CurvePoint? expected), (_, CurvePoint? expectedBase)) in products.Zip(BaseProducts.Value))
			{
				kernel.MultiplyBaseAndFixed(table.Windows, ToScalar(scalar), out JacobianPoint<SM2Field52> baseProduct, out JacobianPoint<SM2Field52> product);
				kernel.Multiply(in affine, ToScalar(scalar), out JacobianPoint<SM2Field52> withoutTable);

				if (!IsOfFormE(in product.X) || !IsOfFormE(in product.Y) || !IsOfFormE(in product.Z) || !IsOfFormE(in baseProduct.X) || !IsOfFormE(in baseProduct.Y) || !IsOfFormE(in baseProduct.Z))
				{
					failures.Add($"{scalar:X} gave limbs outside the form E");
					continue;
				}

				CheckPoint(failures, Curve.Reference, $"{scalar:X} · G", ToValue(in baseProduct), expectedBase);
				CheckPoint(failures, Curve.Reference, $"{scalar:X} · ({point.X:X}, …)", ToValue(in product), expected);

				if (Curve.Reference.ToAffine(ToValue(in product)) != Curve.Reference.ToAffine(ToValue(in withoutTable)))
				{
					failures.Add($"{scalar:X} · ({point.X:X}, …) differs from Multiply");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// k·P from the windows of P alone, for the scalars of MultiplyBaseMatchesTheReference, whose splits those of P share; the results must be in the form E as well.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task MultiplyFixedMatchesTheReference(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];

		foreach ((CurvePoint point, ECPointTable<SM2Curve, SM2Field52, SM2Order> table, (BigInteger Scalar, CurvePoint? Product)[] products) in FixedProducts.Value)
		{
			foreach ((BigInteger scalar, CurvePoint? expected) in products)
			{
				kernel.MultiplyFixed(table.Windows, ToScalar(scalar), out JacobianPoint<SM2Field52> product);

				if (!IsOfFormE(in product.X) || !IsOfFormE(in product.Y) || !IsOfFormE(in product.Z))
				{
					failures.Add($"{scalar:X} · ({point.X:X}, …) gave limbs outside the form E");
					continue;
				}

				CheckPoint(failures, Curve.Reference, $"{scalar:X} · ({point.X:X}, …)", ToValue(in product), expected);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Q = q·G for a known q, so that u1 = −q·u2 and u1 = q·u2 make the sum of u1·G and u2·Q the point at infinity and a double; with the scalars of the windows of 8 bits of SM2VerificationCurve, which u1·G takes, for u1 and edge cases for u2.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task MultiplyAddMatchesTheReference(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		(AffinePoint<SM2Field52>[] table, Sum[] sums) = TableSums.Value;
		List<string> failures = [];

		foreach ((BigInteger u1, BigInteger u2, CurvePoint? expected) in sums)
		{
			kernel.MultiplyAdd(ToScalar(u1), table, ToScalar(u2), out JacobianPoint<SM2Field52> result);
			CheckPoint(failures, Curve.Reference, $"{u1:X} · G + {u2:X} · Q", ToValue(in result), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	// As MultiplyAddMatchesTheReference with the windows of Q of SM2VerificationCurve, whose blocks split as those of G of that curve do, so that VerificationScalars serve for u1 and u2 alike, each with a random other; the edge cases of u2 also take u1 = ∓q·u2 and 0, and the results must be in the form E.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task MultiplyAddFixedMatchesTheReference(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		(ECPointTable<SM2VerificationCurve, SM2Field52, SM2Order> table, Sum[] sums) = FixedSums.Value;
		List<string> failures = [];

		foreach ((BigInteger u1, BigInteger u2, CurvePoint? expected) in sums)
		{
			kernel.MultiplyAddFixed(table.Windows, ToScalar(u1), ToScalar(u2), out JacobianPoint<SM2Field52> result);

			if (!IsOfFormE(in result.X) || !IsOfFormE(in result.Y) || !IsOfFormE(in result.Z))
			{
				failures.Add($"{u1:X} · G + {u2:X} · Q gave limbs outside the form E");
				continue;
			}

			CheckPoint(failures, Curve.Reference, $"{u1:X} · G + {u2:X} · Q", ToValue(in result), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	// k·P for G and a random point, with the scalars of the windows of ECGroup.Multiply and of SM2OddWindows; the results must be in the form E as well, and (0, 0, 0) for k = 0.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task MultiplyMatchesTheReference(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];

		foreach ((CurvePoint point, (BigInteger Scalar, CurvePoint? Product)[] products) in PointProducts.Value)
		{
			AffinePoint<SM2Field52> affine = ToPoint(point);

			foreach ((BigInteger scalar, CurvePoint? expected) in products)
			{
				kernel.Multiply(in affine, ToScalar(scalar), out JacobianPoint<SM2Field52> product);

				if (!IsOfFormE(in product.X) || !IsOfFormE(in product.Y) || !IsOfFormE(in product.Z))
				{
					failures.Add($"{scalar:X} · ({point.X:X}, …) gave limbs outside the form E");
					continue;
				}

				if (scalar.IsZero && ToValue(in product) != new JacobianValue(0, 0, 0))
				{
					failures.Add($"0 · ({point.X:X}, …) gave {ToValue(in product)}, not (0, 0, 0)");
				}

				CheckPoint(failures, Curve.Reference, $"{scalar:X} · ({point.X:X}, …)", ToValue(in product), expected);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The chains of SM2OctoFormulas from entries read at public digits, which u1·G + u2·Q without a table takes on AVX-512, for the scalars of MultiplyMatchesTheReference and their exceptions; the results must be in the form E as well, and (0, 0, 0) for k = 0.
	[Test]
	public async Task OctoVariableTimeMatchesTheReference()
	{
		if (!SM2Field29x8Avx512.IsSupported)
		{
			Skip.Test("AVX-512 is not supported here.");
		}

		List<string> failures = [];

		foreach ((CurvePoint point, (BigInteger Scalar, CurvePoint? Product)[] products) in PointProducts.Value)
		{
			AffinePoint<SM2Field52> affine = ToPoint(point);

			foreach ((BigInteger scalar, CurvePoint? expected) in products)
			{
				SM2OctoFormulas.MultiplyVariableTime(in affine, ToScalar(scalar), out JacobianPoint<SM2Field52> product);

				if (!IsOfFormE(in product.X) || !IsOfFormE(in product.Y) || !IsOfFormE(in product.Z) || scalar.IsZero && ToValue(in product) != new JacobianValue(0, 0, 0))
				{
					failures.Add($"{scalar:X} · ({point.X:X}, …) gave limbs outside the form E or not (0, 0, 0)");
					continue;
				}

				CheckPoint(failures, Curve.Reference, $"{scalar:X} · ({point.X:X}, …)", ToValue(in product), expected);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// k·P + l·Q by SM2OctoFormulas.MultiplyAdd, which the key exchange takes on AVX-512 without the windows of the static key of the peer, for Q = c·P: the scalars of MultiplyMatchesTheReference and those at which window 0 of a chain over all the odd digits meets equal points, which must be n − 38 alone, the TwiceLowDigit of SM2OctoFormulas, with their neighbors, each with a random scalar in the other chain; those in both chains; l·Q equal and opposite to k·P; and 0 for k, l or both. The results must be in the form E as well.
	[Test]
	public async Task OctoMultiplyAddMatchesTheReference()
	{
		if (!SM2Field29x8Avx512.IsSupported)
		{
			Skip.Test("AVX-512 is not supported here.");
		}

		BigInteger n = Curve.Order;
		List<BigInteger> equal = TwiceLowDigitScalars();
		Random random = new(17);
		(CurvePoint point, (BigInteger Scalar, CurvePoint? Product)[] products) = PointProducts.Value[1];
		BigInteger c = ECReference.RandomBelow(random, n - 1) + 1;
		CurvePoint other = Curve.Reference.Multiply(point, c) ?? throw new InvalidOperationException("c·P is the point at infinity.");
		BigInteger inverse = ECReference.Inverse(c, n);
		SortedSet<BigInteger> scalars = [.. products.Select(static product => product.Scalar)];

		foreach (BigInteger k in equal)
		{
			for (int s = -2; s <= 2; ++s)
			{
				scalars.Add(k + s);
			}
		}

		BigInteger r = ECReference.RandomBelow(random, n - 1) + 1;
		List<(BigInteger K, BigInteger L)> pairs = [(0, 0), (r, 0), (0, r), (r, r * inverse % n), (r, (n - r * inverse % n) % n)];

		foreach (BigInteger k in scalars)
		{
			pairs.Add((k, ECReference.RandomBelow(random, n)));
			pairs.Add((ECReference.RandomBelow(random, n), k));
		}

		foreach (BigInteger k in equal)
		{
			pairs.Add((k, k));
			pairs.Add((k, k * inverse % n));
		}

		CurvePoint?[] expected = Curve.Reference.Multiply(point, [.. pairs.Select(pair => (pair.K + pair.L * c) % n)]);
		AffinePoint<SM2Field52> affine = ToPoint(point);
		AffinePoint<SM2Field52> otherAffine = ToPoint(other);
		List<string> failures = [];

		for (int i = 0; i < pairs.Count; ++i)
		{
			(BigInteger k, BigInteger l) = pairs[i];
			SM2OctoFormulas.MultiplyAdd(in affine, ToScalar(k), in otherAffine, ToScalar(l), out JacobianPoint<SM2Field52> sum);

			if (!IsOfFormE(in sum.X) || !IsOfFormE(in sum.Y) || !IsOfFormE(in sum.Z))
			{
				failures.Add($"{k:X} · P + {l:X} · Q gave limbs outside the form E");
				continue;
			}

			CheckPoint(failures, Curve.Reference, $"{k:X} · P + {l:X} · Q", ToValue(in sum), expected[i]);
		}

		using (Assert.Multiple())
		{
			await Assert.That(equal).IsEquivalentTo((BigInteger[])[n - 38]);
			await Assert.That(failures).IsEmpty();
		}
	}

	// SM2OddWindows.RecodeHalf writes odd digits in [−31, 31] that sum to an odd k below 2^128: 1, 3, 2^128 − 1 and its odd neighbors, runs of one window value, and random scalars.
	[Test]
	public async Task HalfWindowsSumToTheScalar()
	{
		List<string> failures = [];
		sbyte[] digits = new sbyte[SM2OddWindows.HalfCount];

		foreach (BigInteger scalar in OddHalfScalars())
		{
			SM2OddWindows.RecodeHalf((UInt128)scalar, digits);
			BigInteger sum = SumOfWindows([.. digits.Select(static digit => (int)digit)], OddWidth, 0, digits.Length);

			if (digits.Any(static digit => (digit & 1) is 0 || digit is < -31 or > 31) || sum != scalar)
			{
				failures.Add($"{scalar:X} gave the digits {string.Join(", ", digits)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// ECGroup.RecodeSpanning writes 32 digits for the windows of 8 bits of SM2VerificationCurve, in [−128, 127] as sbyte holds them, that sum to k up to the k whose windows are all 127, the largest those digits reach, and to k − n above it, for VerificationScalars.
	[Test]
	public async Task VerificationWindowsSumToTheScalarOrItLessN()
	{
		BigInteger n = Curve.Order;
		int width = SM2VerificationCurve.GeneratorWindowWidth;
		int count = ECGeneratorTable<SM2VerificationCurve, SM2Field52, SM2Order>.WindowCount;
		BigInteger largest = Repeat((1 << width - 1) - 1, width, 256 / width);
		List<string> failures = [];
		sbyte[] digits = new sbyte[count];

		foreach (BigInteger scalar in VerificationScalars.Value)
		{
			ECGroup<SM2VerificationCurve, SM2Field52, SM2Order>.RecodeSpanning(ToScalar(scalar), width, digits);
			BigInteger sum = SumOfWindows([.. digits.Select(static digit => (int)digit)], width, 0, digits.Length);

			if (sum != (scalar <= largest ? scalar : scalar - n))
			{
				failures.Add($"{scalar:X} gave the digits {string.Join(", ", digits)}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(count).IsEqualTo(32);
			await Assert.That(failures).IsEmpty();
		}
	}

	// The chains of SM2OctoFormulas over the digits of RecodeHalf, which verification takes on AVX-512, k·P in one half and l·Q in the other for two random points, with the scalars of HalfWindowsSumToTheScalar for k, each with a random l, and the same the other way; the results must be in the form E as well.
	[Test]
	public async Task OctoHalfChainsMatchTheReference()
	{
		if (!SM2Field29x8Avx512.IsSupported)
		{
			Skip.Test("AVX-512 is not supported here.");
		}

		Random random = new(19);
		CurvePoint point = Curve.Reference.RandomPoint(random);
		CurvePoint other = Curve.Reference.RandomPoint(random);
		List<(BigInteger K, BigInteger L)> pairs = [];

		foreach (BigInteger scalar in OddHalfScalars())
		{
			BigInteger random1 = ECReference.RandomBelow(random, BigInteger.One << 127) * 2 + 1;
			pairs.Add((scalar, random1));
			pairs.Add((random1, scalar));
		}

		CurvePoint?[] expectedFirst = Curve.Reference.Multiply(point, [.. pairs.Select(static pair => pair.K)]);
		CurvePoint?[] expectedSecond = Curve.Reference.Multiply(other, [.. pairs.Select(static pair => pair.L)]);
		AffinePoint<SM2Field52> affine = ToPoint(point);
		AffinePoint<SM2Field52> otherAffine = ToPoint(other);
		sbyte[] digits = new sbyte[SM2OddWindows.HalfCount];
		sbyte[] otherDigits = new sbyte[SM2OddWindows.HalfCount];
		List<string> failures = [];

		for (int i = 0; i < pairs.Count; ++i)
		{
			(BigInteger k, BigInteger l) = pairs[i];
			SM2OddWindows.RecodeHalf((UInt128)k, digits);
			SM2OddWindows.RecodeHalf((UInt128)l, otherDigits);
			SM2OctoFormulas.MultiplyVariableTime(in affine, digits, in otherAffine, otherDigits, out JacobianPoint<SM2Field52> first, out JacobianPoint<SM2Field52> second);

			if (!IsOfFormE(in first.X) || !IsOfFormE(in first.Y) || !IsOfFormE(in first.Z) || !IsOfFormE(in second.X) || !IsOfFormE(in second.Y) || !IsOfFormE(in second.Z))
			{
				failures.Add($"{k:X} · P and {l:X} · Q gave limbs outside the form E");
				continue;
			}

			CheckPoint(failures, Curve.Reference, $"{k:X} · P", ToValue(in first), expectedFirst[i]);
			CheckPoint(failures, Curve.Reference, $"{l:X} · Q", ToValue(in second), expectedSecond[i]);
		}

		await Assert.That(failures).IsEmpty();
	}

	// The bound from which the AVX-512 kernel of verification takes r for the only x below p that is r mod n.
	[Test]
	public async Task FieldGapIsTheDifferenceOfTheModuli()
	{
		await Assert.That(ModulusCase.FromLimbs(SM2Avx512.FieldGap)).IsEqualTo(Curve.Reference.P - Curve.Order);
	}

	// The comparison of the AVX-512 kernel that verification takes against the reference, for Q = u2⁻¹·(S − u1·G) with random u1 and u2 and a chosen sum S: S of x at r and at r + n for r below p − n, where the kernel goes to MultiplyAdd, and S of x at p − n and above; for each, r that is the x of S mod n, r + 1 and r − 1. Random Q with the x of the sum and with random r, which takes v1 and v2 of each parity, r with no point of x r, sums at the point at infinity, and u1 or u2 of 0 complete it.
	[Test]
	public async Task OctoVerificationMatchesTheReference()
	{
		if (!SM2Field29x8Avx512.IsSupported)
		{
			Skip.Test("AVX-512 is not supported here.");
		}

		BigInteger n = Curve.Order;
		BigInteger p = Curve.Reference.P;
		Random random = new(29);
		List<(BigInteger U1, CurvePoint Q, BigInteger U2, BigInteger R)> cases = [];
		CurvePoint[] sums = [Curve.Reference.PointWithXFrom(1), Curve.Reference.PointWithXFrom(p - n - 3), Curve.Reference.PointWithXFrom(p - n), Curve.Reference.PointWithXFrom(n), Curve.Reference.PointWithXFrom(n - 5), Curve.Reference.RandomPoint(random)];
		(BigInteger U1, BigInteger U2, CurvePoint Sum)[] chosen = [.. sums.SelectMany(sum => Enumerable.Range(0, 4).Select(i => (i is 0 ? 0 : ECReference.RandomBelow(random, n), ECReference.RandomBelow(random, n - 1) + 1, sum)))];
		CurvePoint?[] differences = Curve.Reference.Add([.. chosen.Select(static c => (CurvePoint?)c.Sum)], [.. Curve.Reference.Multiply(Curve.Reference.Generator, [.. chosen.Select(static c => c.U1)]).Select(Curve.Reference.Negate)]);
		CurvePoint?[] chosenQ = Curve.Reference.Multiply(differences, [.. chosen.Select(c => ECReference.Inverse(c.U2, n))]);

		for (int i = 0; i < chosen.Length; ++i)
		{
			(BigInteger u1, BigInteger u2, CurvePoint sum) = chosen[i];
			BigInteger r = sum.X % n;

			foreach (BigInteger candidate in (BigInteger[])[r, (r + 1) % n, (r + n - 1) % n])
			{
				cases.Add((u1, chosenQ[i] ?? throw new InvalidOperationException("Q is the point at infinity."), u2, candidate));
			}
		}

		(BigInteger U1, BigInteger U2, BigInteger QScalar, BigInteger OtherR)[] drawn = [.. Enumerable.Range(0, 4 * RandomCount).Select(i => (ECReference.RandomBelow(random, n), i % 8 is 0 ? i / 8 : ECReference.RandomBelow(random, n), ECReference.RandomBelow(random, n - 1) + 1, i % 2 is 0 ? 0 : ECReference.RandomBelow(random, n)))];
		CurvePoint?[] randomQ = Curve.Reference.Multiply(Curve.Reference.Generator, [.. drawn.Select(static d => d.QScalar)]);
		CurvePoint?[] randomSums = LinearSums([.. drawn.Select(static d => d.U1)], randomQ, [.. drawn.Select(static d => d.U2)]);

		for (int i = 0; i < drawn.Length; ++i)
		{
			BigInteger r = i % 2 is 0 && randomSums[i] is { } sum ? sum.X % n : drawn[i].OtherR;
			cases.Add((drawn[i].U1, randomQ[i] ?? throw new InvalidOperationException("Q is the point at infinity."), drawn[i].U2, r));
		}

		// No point has an x of r here, and the sums of the last cases are the point at infinity.
		BigInteger missing = p - n;

		while (Curve.Reference.SquareRoot(Curve.Reference.Mod(missing * missing * missing - 3 * missing + Curve.Reference.B)) is not null)
		{
			++missing;
		}

		CurvePoint infinityQ = Curve.Reference.Multiply(Curve.Reference.Generator, 5) ?? throw new InvalidOperationException("Q is the point at infinity.");
		cases.Add((7, infinityQ, 9, missing));
		cases.Add((n - 5, infinityQ, 1, 0));
		cases.Add((n - 5, infinityQ, 1, n - 1));
		cases.Add((0, infinityQ, 0, 0));
		CurvePoint?[] caseSums = LinearSums([.. cases.Select(static c => c.U1)], [.. cases.Select(static c => (CurvePoint?)c.Q)], [.. cases.Select(static c => c.U2)]);
		List<string> failures = [];
		int matches = 0;

		for (int i = 0; i < cases.Count; ++i)
		{
			(BigInteger u1, CurvePoint q, BigInteger u2, BigInteger r) = cases[i];
			bool expected = caseSums[i] is { } sum && sum.X % n == r;
			bool actual = SM2Avx512.MultiplyAddXModOrderEquals(ToScalar(u1), ToPoint(q), ToScalar(u2), ToScalar(r));
			matches += expected ? 1 : 0;

			if (actual != expected)
			{
				failures.Add($"{u1:X} · G + {u2:X} · ({q.X:X}, …) against {r:X} gave {actual}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(matches).IsGreaterThan(cases.Count / 4);
		}
	}

	// As MultiplyAddMatchesTheReference without the table of Q, with the scalars of the windows of ECGroup.Multiply and some of VerificationScalars for u1.
	[Test]
	[MethodDataSource(typeof(SM2KernelCase), nameof(SM2KernelCase.All))]
	public async Task MultiplyAddWithoutTableMatchesTheReference(SM2KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		(AffinePoint<SM2Field52> affine, Sum[] sums) = PointSums.Value;
		List<string> failures = [];

		foreach ((BigInteger u1, BigInteger u2, CurvePoint? expected) in sums)
		{
			kernel.MultiplyAdd(ToScalar(u1), in affine, ToScalar(u2), out JacobianPoint<SM2Field52> result);
			CheckPoint(failures, Curve.Reference, $"{u1:X} · G + {u2:X} · Q", ToValue(in result), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	// The lanes of the vector kernels fold sums of blocks of windows of w bits, and the last fold would add equal points at k = n − 2·(n mod 2^(wb)) for a split after b windows if bit wb − 1 of n were 0. The scalars of MultiplyBaseMatchesTheReference hold that k for every b; this test checks, for both widths, that the reference does meet equal points there for the splits that would be wrong, and that the last folds of eight, four and two blocks split elsewhere, so that those scalars keep their point.
	[Test]
	[Arguments(6)]
	[Arguments(7)]
	public async Task SplitScalarsMeetEqualPointsWhereBitsOfNAreClear(int width)
	{
		BigInteger n = Curve.Order;
		int windowCount = 256 / width + 1;
		List<int> clear = [];

		for (int b = 1; b < windowCount; ++b)
		{
			BigInteger low = n % (BigInteger.One << width * b);
			BigInteger k = n - 2 * low;
			BigInteger lowSum = SumOfWindows(Recode(k, width, windowCount), width, 0, b);
			BigInteger highSum = k - lowSum;

			if ((lowSum - highSum) % n == 0 && lowSum % n != 0)
			{
				clear.Add(b);
			}
		}

		// The last fold of a blocks adds the first a/2 of them, the first W mod a blocks one window longer.
		int[] splits = [.. ((int[])[8, 4, 2]).Select(blocks => blocks / 2 * (windowCount / blocks) + Math.Min(blocks / 2, windowCount % blocks))];
		await Assert.That(clear).IsNotEmpty().And.DoesNotContain(splits[0]).And.DoesNotContain(splits[1]).And.DoesNotContain(splits[2]);
	}

	// SM2OddWindows writes digits d_i, odd and in [−31, 31], with Σ d_i·32^i = 2s − (2^260 − 1) for s = (k + 2^260 − 1)/2 mod n, plus n at its exception alone.
	[Test]
	public async Task OddWindowsSumToTheScalar()
	{
		List<string> failures = [];
		sbyte[] digits = new sbyte[SM2OddWindows.Count];

		foreach (BigInteger scalar in PointScalars())
		{
			SM2OddWindows.Recode(ToScalar(scalar), digits);
			BigInteger sum = SumOfWindows([.. digits.Select(static digit => (int)digit)], OddWidth, 0, digits.Length);
			BigInteger expected = 2 * OddS(scalar) - ((BigInteger.One << OddWidth * SM2OddWindows.Count) - 1);

			if (digits.Any(static digit => (digit & 1) is 0 || digit is < -31 or > 31) || sum != expected)
			{
				failures.Add($"{scalar:X} gave the digits {string.Join(", ", digits)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The AVX-512 kernel adds 2^130·T·P to B·P for the sums T and B of the odd digits from 26 up and below, 2^130·T + B = 2s − (2^260 − 1), and equal points need 2^130·T − B = jn for an odd j. Over every such j within the bounds of 2^130·T − B, s below n meets equal points at one k, which must be the exception of SM2OddWindows, and s in [n, 2n), which the exception takes, at one other k; the scalars of PointScalars hold both, and also the bits of n that the bounds of SM2OctoFormulas.Multiply take.
	[Test]
	public async Task OddWindowsMeetEqualPointsJustAtTheException()
	{
		BigInteger n = Curve.Order;
		List<BigInteger> below = EqualScalars(0);
		List<BigInteger> above = EqualScalars(1);

		await Assert.That(below).IsEquivalentTo((BigInteger[])[SplitException]);
		await Assert.That(above).HasSingleItem().And.DoesNotContain(SplitException);
		await Assert.That(OddS(SplitException) >= n && OddS(above[0]) < n).IsTrue();
		await Assert.That(n >> 130 >= (BigInteger.One << 126) - (BigInteger.One << 95)).IsTrue();
	}

	// u1·G + u2·Q for each triple, at once.
	private static CurvePoint?[] LinearSums(BigInteger[] u1s, CurvePoint?[] points, BigInteger[] u2s)
	{
		return Curve.Reference.Add(Curve.Reference.Multiply(Curve.Reference.Generator, u1s), Curve.Reference.Multiply(points, u2s));
	}

	// The k with s in [mn, (m + 1)n) at which the sums of the chains are equal points.
	private static List<BigInteger> EqualScalars(int m)
	{
		BigInteger n = Curve.Order;
		BigInteger half = BigInteger.One << 130;
		BigInteger offset = half - 1;
		BigInteger lowest = (2 * (m * n >> 130) - offset) * half - offset;
		BigInteger highest = (2 * ((m + 1) * n - 1 >> 130) - offset) * half + offset;
		List<BigInteger> scalars = [];

		for (BigInteger j = BigInteger.Divide(lowest, n) - 1; j * n <= highest; ++j)
		{
			if (j * n < lowest || j.IsEven)
			{
				continue;
			}

			BigInteger residue = BigInteger.Remainder(BigInteger.Remainder(-j * n, half) + half, half);

			foreach (BigInteger b in (BigInteger[])[residue, residue - half])
			{
				BigInteger t = (j * n + b) / half;
				BigInteger s = ((t + offset) / 2 << 130) + (b + offset) / 2;

				if (!t.IsEven && !b.IsEven && s >= m * n && s < (m + 1) * n)
				{
					BigInteger k = BigInteger.Remainder((t << 130) + b, n);
					scalars.Add(k < 0 ? k + n : k);
				}
			}
		}

		return scalars;
	}

	// The k at which window 0 of a chain over all the odd digits of k adds equal points, 32a·P = d_0·P with k ≡ 32a + d_0 (mod n): k ≡ 2d_0 for its low digit d_0, so k = 2d mod n for an odd d in [−31, 31] whose low digit is d.
	private static List<BigInteger> TwiceLowDigitScalars()
	{
		BigInteger n = Curve.Order;
		List<BigInteger> scalars = [];

		for (int d = -31; d <= 31; d += 2)
		{
			BigInteger k = (2 * d + n) % n;

			if (2 * (int)(OddS(k) & 31) - 31 == d)
			{
				scalars.Add(k);
			}
		}

		return scalars;
	}

	// The s of SM2OddWindows for k: (k + 2^260 − 1)/2 mod n, plus n at the exception.
	private static BigInteger OddS(BigInteger scalar)
	{
		BigInteger n = Curve.Order;
		BigInteger s = (scalar + (BigInteger.One << OddWidth * SM2OddWindows.Count) - 1) * ((n + 1) / 2) % n;
		return scalar == SplitException ? s + n : s;
	}

	private static (AffinePoint<SM2Field52>[], Sum[]) ComputeTableSums()
	{
		BigInteger n = Curve.Order;
		Random random = new(12);
		(BigInteger q, CurvePoint point) = RandomMultiple(random);
		List<(BigInteger, BigInteger)> pairs = [];

		foreach (BigInteger u2 in (BigInteger[])[0, 1, n - 1, ECReference.RandomBelow(random, n)])
		{
			AddEdgeSums(pairs, q, u2);

			foreach (BigInteger u1 in VerificationScalars.Value.Where(static (_, i) => i % 23 is 0))
			{
				pairs.Add((u1, u2));
			}
		}

		return (ECVariableTimePointTable<SM2Curve, SM2Field52, SM2Order>.Build(ToPoint(point)), WithSums(q, pairs));
	}

	private static (ECPointTable<SM2VerificationCurve, SM2Field52, SM2Order>, Sum[]) ComputeFixedSums()
	{
		BigInteger n = Curve.Order;
		Random random = new(17);
		(BigInteger q, CurvePoint point) = RandomMultiple(random);
		List<(BigInteger, BigInteger)> pairs = [];

		foreach (BigInteger u2 in (BigInteger[])[0, 1, 2, n - 1, ECReference.RandomBelow(random, n)])
		{
			AddEdgeSums(pairs, q, u2);
		}

		foreach (BigInteger scalar in VerificationScalars.Value.Where(static (_, i) => i % 3 is 0))
		{
			pairs.Add((scalar, ECReference.RandomBelow(random, n)));
			pairs.Add((ECReference.RandomBelow(random, n), scalar));
		}

		return (new ECPointTable<SM2VerificationCurve, SM2Field52, SM2Order>(ToPoint(point)), WithSums(q, pairs));
	}

	private static (AffinePoint<SM2Field52>, Sum[]) ComputePointSums()
	{
		BigInteger n = Curve.Order;
		Random random = new(13);
		(BigInteger q, CurvePoint point) = RandomMultiple(random);
		List<(BigInteger, BigInteger)> pairs = [];

		foreach (BigInteger u2 in (BigInteger[])[0, 1, 2, n - 1, ECReference.RandomBelow(random, n)])
		{
			AddEdgeSums(pairs, q, u2);

			foreach (BigInteger u1 in PointProducts.Value[0].Products.Where(static (_, i) => i % 11 is 0).Select(static product => product.Scalar).Concat(VerificationScalars.Value.Where(static (_, i) => i % 29 is 0)))
			{
				pairs.Add((u1, u2));
			}
		}

		return (ToPoint(point), WithSums(q, pairs));
	}

	private static (BigInteger Q, CurvePoint Point) RandomMultiple(Random random)
	{
		BigInteger q = ECReference.RandomBelow(random, Curve.Order - 1) + 1;
		return (q, Curve.Reference.Multiply(Curve.Reference.Generator, q) ?? throw new InvalidOperationException("q·G is the point at infinity."));
	}

	// u1 = −q·u2, q·u2 and 0, which make the sum of u1·G and u2·q·G the point at infinity, a double and u2·Q alone.
	private static void AddEdgeSums(List<(BigInteger, BigInteger)> pairs, BigInteger q, BigInteger u2)
	{
		BigInteger n = Curve.Order;
		pairs.Add(((n - q * u2 % n) % n, u2));
		pairs.Add((q * u2 % n, u2));
		pairs.Add((0, u2));
	}

	private static Sum[] WithSums(BigInteger q, List<(BigInteger U1, BigInteger U2)> pairs)
	{
		BigInteger n = Curve.Order;
		CurvePoint?[] expected = Curve.Reference.Multiply(Curve.Reference.Generator, [.. pairs.Select(pair => (pair.U1 + q * pair.U2) % n)]);
		return [.. pairs.Zip(expected, static (pair, sum) => new Sum(pair.U1, pair.U2, sum))];
	}

	private static (BigInteger, CurvePoint?)[] ComputeBaseProducts()
	{
		BigInteger[] scalars = [.. Scalars(WindowWidth)];
		return [.. scalars.Zip(Curve.Reference.Multiply(Curve.Reference.Generator, scalars))];
	}

	private static (CurvePoint, ECPointTable<SM2Curve, SM2Field52, SM2Order>, (BigInteger, CurvePoint?)[])[] ComputeFixedProducts()
	{
		BigInteger[] scalars = [.. Scalars(WindowWidth)];
		Random random = new(16);
		CurvePoint[] points = [.. Enumerable.Range(0, 2).Select(_ => Curve.Reference.Multiply(Curve.Reference.Generator, ECReference.RandomBelow(random, Curve.Order - 1) + 1) ?? throw new InvalidOperationException("The point is the point at infinity."))];
		return [.. points.Select(point => (point, new ECPointTable<SM2Curve, SM2Field52, SM2Order>(ToPoint(point)), ((BigInteger, CurvePoint?)[])[.. scalars.Zip(Curve.Reference.Multiply(point, scalars))]))];
	}

	private static (CurvePoint, (BigInteger, CurvePoint?)[])[] ComputePointProducts()
	{
		BigInteger[] scalars = [.. PointScalars()];
		CurvePoint other = Curve.Reference.Multiply(Curve.Reference.Generator, ECReference.RandomBelow(new Random(14), Curve.Order - 1) + 1) ?? throw new InvalidOperationException("The point is the point at infinity.");
		return [.. ((CurvePoint[])[Curve.Reference.Generator, other]).Select(point => (point, ((BigInteger, CurvePoint?)[])[.. scalars.Zip(Curve.Reference.Multiply(point, scalars))]))];
	}

	// Odd scalars below 2^128 for RecodeHalf: 1, 3 and 5; 2^128 − 1, 2^127 ± 1 and 2^125 ± 1, at the windows of the top digit; scalars of one window value v in every window below the top, for v = 0, 15, 16 and 31, the smallest, middle and largest digits; and random ones.
	private static SortedSet<BigInteger> OddHalfScalars()
	{
		BigInteger half = BigInteger.One << 128;
		SortedSet<BigInteger> scalars = [1, 3, 5, half - 1, half - 3, (half >> 1) - 1, (half >> 1) + 1, (half >> 3) - 1, (half >> 3) + 1];

		foreach (int window in (int[])[0, 15, 16, 31])
		{
			BigInteger repeated = 0;

			for (int i = 0; i < SM2OddWindows.HalfCount - 1; ++i)
			{
				repeated |= (BigInteger)window << OddWidth * i;
			}

			// The digits come from (k − 1)/2, whose windows these are.
			scalars.Add(2 * repeated + 1);
		}

		Random random = new(18);

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(ECReference.RandomBelow(random, half >> 1) * 2 + 1);
		}

		return scalars;
	}

	// For the windows of 5 bits of ECGroup.Multiply: 0, small scalars, whose top digits are 0, and the largest ones, n − 6 among them, whose window 0 adds equal points; 2^(5i) and n − 2^(5i) with their neighbors; n − 2·(n mod 2^130) and 2·(n mod 2^130) with their neighbors; windows of 16, 17 and 31, the largest digit and the most negative ones with carries. For the odd windows of SM2OddWindows: the scalars at which its chains would meet equal points, for s below n and for s in [n, 2n), with their neighbors; those of s = 0, s = n − 1 and s = 2^130 − 1 and 2^130, the extremes of the digits and of the bottom chain; and random scalars.
	private static SortedSet<BigInteger> PointScalars()
	{
		const int width = 5;
		BigInteger n = Curve.Order;
		SortedSet<BigInteger> scalars = [n - 1, n - 2, n - 3, n - 5, n - 6, n - 7, (n - 1) / 2, (n + 1) / 2];

		for (int k = 0; k <= 40; ++k)
		{
			scalars.Add(k);
		}

		for (int i = 1; i * width < 256; ++i)
		{
			BigInteger power = BigInteger.One << width * i;

			for (int s = -1; s <= 1; ++s)
			{
				scalars.Add(power + s);
				scalars.Add(n - power + s);
			}
		}

		// Around the split of the AVX-512 kernel after 26 windows.
		BigInteger low = n % (BigInteger.One << 130);

		for (int s = -2; s <= 2; ++s)
		{
			scalars.Add(n - 2 * low + s);
			scalars.Add(2 * low + s);
		}

		foreach (BigInteger equal in EqualScalars(0).Concat(EqualScalars(1)))
		{
			for (int s = -2; s <= 2; ++s)
			{
				scalars.Add(equal + s);
			}
		}

		// k = 2s − (2^260 − 1) mod n.
		foreach (BigInteger s in (BigInteger[])[0, n - 1, (BigInteger.One << 130) - 1, BigInteger.One << 130])
		{
			BigInteger k = BigInteger.Remainder(2 * s - (BigInteger.One << OddWidth * SM2OddWindows.Count) + 1, n);
			scalars.Add(k < 0 ? k + n : k);
		}

		foreach (int window in (int[])[16, 17, 31])
		{
			BigInteger repeated = 0;

			for (int i = 0; i * width < 256; ++i)
			{
				BigInteger next = repeated | (BigInteger)window << width * i;

				if (next >= n)
				{
					break;
				}

				repeated = next;
			}

			scalars.Add(repeated);
		}

		Random random = new(15);

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(ECReference.RandomBelow(random, n));
		}

		scalars.RemoveWhere(scalar => scalar < 0 || scalar >= n);
		return scalars;
	}

	// 0 and the largest scalars; around each split after b windows, 2^(wb) and n − 2^(wb) with their neighbors and k = n − 2·(n mod 2^(wb)), at which a fold of the low and the high windows meets equal points where bit wb − 1 of n is 0; windows of h = 2^(w − 1), h + 1 and 2h − 1, the largest digit and the most negative ones with carries; where w divides 256, the largest k whose digits are those of k, every window h − 1, with its neighbors, and the k whose digits, those of k − n, are −h and then 1 − h in every window above, or h − 1 below a top one of −h; and random scalars.
	private static SortedSet<BigInteger> Scalars(int width)
	{
		BigInteger n = Curve.Order;
		int windowCount = (256 + width - 1) / width;
		SortedSet<BigInteger> scalars = [0, 1, 2, 3, n - 1, n - 2, n - 3, n - 6, (n - 1) / 2, (n + 1) / 2];

		for (int b = 1; b < windowCount; ++b)
		{
			BigInteger power = BigInteger.One << width * b;
			BigInteger low = n % power;

			for (int s = -2; s <= 2; ++s)
			{
				scalars.Add(n - 2 * low + s);
				scalars.Add(2 * low + s);
				scalars.Add(power + s);
				scalars.Add(n - power + s);
			}
		}

		int half = 1 << width - 1;

		foreach (int window in (int[])[half, half + 1, 2 * half - 1])
		{
			BigInteger repeated = 0;

			for (int i = 0; i < windowCount; ++i)
			{
				BigInteger next = repeated | (BigInteger)window << width * i;

				if (next >= n)
				{
					break;
				}

				repeated = next;
			}

			scalars.Add(repeated);
		}

		if (256 % width is 0)
		{
			BigInteger largest = Repeat(half - 1, width, windowCount);
			BigInteger top = (BigInteger)half << width * (windowCount - 1);

			for (int s = -2; s <= 2; ++s)
			{
				scalars.Add(largest + s);
			}

			scalars.Add(Repeat(half, width, windowCount) + n - (BigInteger.One << 256));
			scalars.Add(Repeat(half - 1, width, windowCount - 1) + top + n - (BigInteger.One << 256));
		}

		Random random = new(11);

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(ECReference.RandomBelow(random, n));
		}

		scalars.RemoveWhere(scalar => scalar < 0 || scalar >= n);
		return scalars;
	}

	// count windows of width bits, each of value window.
	private static BigInteger Repeat(int window, int width, int count)
	{
		BigInteger result = 0;

		for (int i = 0; i < count; ++i)
		{
			result |= (BigInteger)window << width * i;
		}

		return result;
	}

	// The digits of ECGroup.Recode for windows of width bits, from [1 − 2^(width − 1), 2^(width − 1)].
	private static int[] Recode(BigInteger scalar, int width, int count)
	{
		int half = 1 << width - 1;
		int[] digits = new int[count];
		int carry = 0;

		for (int i = 0; i < digits.Length; ++i)
		{
			int value = (int)(scalar >> width * i & (1 << width) - 1) + carry;
			carry = value > half ? 1 : 0;
			digits[i] = value - (carry << width);
		}

		return digits;
	}

	private static BigInteger SumOfWindows(int[] digits, int width, int start, int end)
	{
		BigInteger sum = 0;

		for (int i = start; i < end; ++i)
		{
			sum += (BigInteger)digits[i] << width * i;
		}

		return sum;
	}

	private static FieldElement<SM2Order> ToScalar(BigInteger value)
	{
		if (!FieldElement<SM2Order>.TryImport(CurveCase.EncodeInteger(value, SM2Order.ByteLength), out FieldElement<SM2Order> scalar))
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, "The scalar is not below n.");
		}

		return scalar;
	}

	private static AffinePoint<SM2Field52> ToPoint(CurvePoint point)
	{
		return new AffinePoint<SM2Field52> { X = ToElement<SM2Field52>(point.X), Y = ToElement<SM2Field52>(point.Y) };
	}

	private static JacobianValue ToValue(in JacobianPoint<SM2Field52> point)
	{
		return new JacobianValue(FieldValue(in point.X), FieldValue(in point.Y), FieldValue(in point.Z));
	}

	private static bool IsOfFormE(in SM2Field52 element)
	{
		return element is { L0: < 1UL << 53, L1: < 1UL << 53, L2: < 1UL << 53, L3: < 1UL << 53, L4: < 1UL << 50 };
	}
}
