using CryptoBase.EllipticCurves.Curve25519;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Field25519TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

// Each four-lane field against BigInteger, lane by lane. The operands of every product of the point formulas and the ladder feed that product, from tight elements with every limb at its largest, zero and random; every result must extract to tight elements. The bound tests write raw limbs instead: products take operands at the largest limbs that Multiply takes, the steps start from the largest limbs of a reduced value, and every operand and product must keep its limbs within its bound. Field25519x8Avx512 runs the point formulas in each of its groups, with other lanes in the other group.
public class Field25519x4Test
{
	private const int RandomCount = 6;

	private const uint A24 = 121665;

	[Test]
	public async Task EveryFieldIsListed()
	{
		SkipUnlessJit();
		Type[] implementations = ImplementationsOf(typeof(IField25519x4<>));
		Type[] pointFields = ImplementationsOf(typeof(IEdwardsField25519x4<>));

		using (Assert.Multiple())
		{
			await Assert.That(Field25519x4Case.All().Select(static field => field.FieldType)).IsEquivalentTo(implementations);
			await Assert.That(pointFields.Except(implementations)).IsEquivalentTo([typeof(Field25519x8Avx512)]);
		}
	}

	[Test]
	[MethodDataSource(typeof(Field25519x4Case), nameof(Field25519x4Case.All))]
	public async Task CreateAndExtractKeepTheLanes(Field25519x4Case field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new RoundTrip())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field25519x4Case), nameof(Field25519x4Case.All))]
	public async Task ProductsMatchBigInteger(Field25519x4Case field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new Products())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field25519x4Case), nameof(Field25519x4Case.All))]
	public async Task PointStepsMatchBigInteger(Field25519x4Case field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new PointSteps())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field25519x4Case), nameof(Field25519x4Case.All))]
	public async Task LadderStepsMatchBigInteger(Field25519x4Case field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new LadderSteps())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field25519x4Case), nameof(Field25519x4Case.All))]
	public async Task StepsAtTheirBoundsMatchBigInteger(Field25519x4Case field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new BoundSteps())).IsEmpty();
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	public async Task EachGroupOfEightLanesHoldsTheBounds(int group)
	{
		Skip.Unless(Field25519x8Avx512.IsSupported, "Field25519x8Avx512 is not supported here.");

		// The other group holds other limbs, so that a result that crosses the halves shows.
		ulong[][] other = [ReducedMaximum, LeftMaximum, Zero, RightMaximum];
		List<string> failures = [];
		RunBoundPointSteps<Field25519x8Avx512>(failures, (limb, lane) => limb * 8 + group * 4 + lane, other, (limb, lane) => limb * 8 + (1 - group) * 4 + lane);
		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	public async Task EachGroupOfEightLanesMatchesBigInteger(int group)
	{
		Skip.Unless(Field25519x8Avx512.IsSupported, "Field25519x8Avx512 is not supported here.");

		List<Field25519[]> all = Lanes();
		List<string> failures = [];

		for (int k = 0; k < all.Count; ++k)
		{
			Field25519[] other = all[(k + 2) % all.Count];
			Func<Field25519[], Field25519x8Avx512> create = lanes => CreateGroup(lanes, other, group);
			Func<Field25519x8Avx512, Field25519[]> extract = value => ExtractGroup(value, group);
			RunPointSteps(failures, all, k, create, extract);
			Field25519x8Avx512 left = create(all[k]);
			Field25519x8Avx512 right = create(other);
			BigInteger[] l = Values(all[k]);
			BigInteger[] r = Values(other);
			Field25519x8Avx512.Multiply(in left, in right, out Field25519x8Avx512 product);
			Check(failures, $"group {group}, Multiply {Show(all[k])}; {Show(other)}", extract(product), l[0] * r[0], l[1] * r[1], l[2] * r[2], l[3] * r[3]);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Lanes with every limb at its largest, 2^255 − 1, and zero in the orders that drive each step to its bounds, then tight elements of every kind.
	private static List<Field25519[]> Lanes()
	{
		Random random = new(7);
		List<Field25519> values = TightElements(random, RandomCount);
		Field25519 largest = Limbs((1UL << 51) - 1, (1UL << 51) - 1, (1UL << 51) - 1, (1UL << 51) - 1, (1UL << 51) - 1);
		Field25519 zero = Element(0);
		List<Field25519[]> lanes = [[largest, zero, largest, largest], [zero, largest, largest, zero], [largest, largest, largest, largest], [zero, zero, zero, zero], [largest, zero, zero, largest]];

		for (int i = 0; i < values.Count; ++i)
		{
			lanes.Add([values[i], values[(i + 1) % values.Count], values[(i + 3) % values.Count], values[(i + 7) % values.Count]]);
		}

		return lanes;
	}

	private static Type[] ImplementationsOf(Type genericInterface)
	{
		return genericInterface.Assembly.GetTypes().Where(type => type is { IsInterface: false, IsAbstract: false } && type.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == genericInterface)).ToArray();
	}

	private static BigInteger[] Values(Field25519[] lanes)
	{
		return [ValueOf(lanes[0]), ValueOf(lanes[1]), ValueOf(lanes[2]), ValueOf(lanes[3])];
	}

	private static string Show(Field25519[] lanes)
	{
		return string.Join(", ", lanes.Select(static lane => Field25519TestUtils.Show(in lane)));
	}

	private static TField Create<TField>(Field25519[] lanes) where TField : unmanaged, IField25519x4<TField>
	{
		TField.Create(in lanes[0], in lanes[1], in lanes[2], in lanes[3], out TField result);
		return result;
	}

	private static Field25519[] Extract<TField>(TField value) where TField : unmanaged, IField25519x4<TField>
	{
		TField.Extract(in value, out Field25519 a, out Field25519 b, out Field25519 c, out Field25519 d);
		return [a, b, c, d];
	}

	private static Field25519x8Avx512 CreateGroup(Field25519[] lanes, Field25519[] other, int group)
	{
		Field25519[] low = group is 0 ? lanes : other;
		Field25519[] high = group is 0 ? other : lanes;
		Field25519x8Avx512.Create(in low[0], in low[1], in low[2], in low[3], in high[0], in high[1], in high[2], in high[3], out Field25519x8Avx512 result);
		return result;
	}

	private static Field25519[] ExtractGroup(Field25519x8Avx512 value, int group)
	{
		Field25519x8Avx512.Extract(in value, group, out Field25519 a, out Field25519 b, out Field25519 c, out Field25519 d);
		return [a, b, c, d];
	}

	private static void Check(List<string> failures, string operation, Field25519[] lanes, params BigInteger[] expected)
	{
		for (int i = 0; i < lanes.Length; ++i)
		{
			if (Mod(ValueOf(lanes[i])) != Mod(expected[i]) || !IsTight(lanes[i]))
			{
				failures.Add($"{operation}, lane {i}: {Field25519TestUtils.Show(in lanes[i])}, expected {Mod(expected[i]):X}");
			}
		}
	}

	// A doubling of lanes all[k] and its readdition of the cached point of other lanes and, where negateCached is given, of that negated, each from its operands to the product that takes them.
	private static void RunPointSteps<TField>(List<string> failures, List<Field25519[]> all, int k, Func<Field25519[], TField> create, Func<TField, Field25519[]> extract, Func<TField, TField>? negateCached = null) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		Field25519[] lanes = all[k];
		string name = Show(lanes);
		TField point = create(lanes);
		BigInteger[] v = Values(lanes);
		DoubleOperands(failures, $"DoubleOperands {name}", point, [v[0] * v[0], v[1] * v[1], v[2] * v[2], -(v[0] + v[1]) * (v[0] + v[1])], extract);
		Field25519[] other = all[(k + 5) % all.Count];
		TField cached = create(other);
		BigInteger[] c = Values(other);
		AddOperands(failures, $"AddOperands {name}; {Show(other)}", point, cached, [(v[1] - v[0]) * c[0], (v[1] + v[0]) * c[1], v[2] * c[2], v[3] * c[3]], extract);

		if (negateCached is not null)
		{
			AddOperands(failures, $"AddOperands {name}; negated {Show(other)}", point, negateCached(cached), [(v[1] - v[0]) * c[1], (v[1] + v[0]) * c[0], v[2] * c[2], -v[3] * c[3]], extract);
		}
	}

	// s holds (S1, S2, S3, −S4).
	private static void DoubleOperands<TField>(List<string> failures, string operation, TField point, BigInteger[] s, Func<TField, Field25519[]> extract) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		BigInteger s5 = s[0] + s[1];
		BigInteger s6 = s[0] - s[1];
		BigInteger s8 = s6 + 2 * s[2];
		BigInteger s9 = s5 + s[3];
		TField.DoubleOperands(in point, out TField left, out TField right);
		Check(failures, $"{operation}, left", extract(left), s8, s5, s8, s5);
		Check(failures, $"{operation}, right", extract(right), s9, s6, s6, s9);
		TField.Multiply(in left, in right, out TField product);
		Check(failures, $"{operation}, product", extract(product), s8 * s9, s5 * s6, s8 * s6, s5 * s9);
	}

	// s holds (S8, S9, S10, S11).
	private static void AddOperands<TField>(List<string> failures, string operation, TField point, TField cached, BigInteger[] s, Func<TField, Field25519[]> extract) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		BigInteger s12 = s[1] - s[0];
		BigInteger s13 = s[1] + s[0];
		BigInteger s14 = s[2] - s[3];
		BigInteger s15 = s[2] + s[3];
		TField.AddOperands(in point, in cached, out TField left, out TField right);
		Check(failures, $"{operation}, left", extract(left), s12, s15, s15, s12);
		Check(failures, $"{operation}, right", extract(right), s14, s13, s14, s13);
		TField.Multiply(in left, in right, out TField product);
		Check(failures, $"{operation}, product", extract(product), s12 * s14, s15 * s13, s15 * s14, s12 * s13);
	}

	// Limb i weighs 2^⌈25.5i⌉; its nominal size is 2^26 if i is even and 2^25 if it is odd.
	private static readonly int[] LimbShifts = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230];

	// The largest limbs of a reduced value, which a product may leave: limbs 0 and 1 below their nominal size plus 2^17.3, and every other below its nominal size plus 2^13 + 1.
	private static readonly ulong[] ReducedMaximum = [.. Enumerable.Range(0, 10).Select(static i => i < 2 ? (ulong)Math.Ceiling(Nominal(i) + Math.Pow(2, 17.3)) - 1 : Nominal(i) + (1UL << 13))];

	// The largest limbs of the left and the right operand of Multiply: m_x = 5.02 and m_y = 3.02 times the nominal sizes.
	private static readonly ulong[] LeftMaximum = Scaled(5.02);

	private static readonly ulong[] RightMaximum = Scaled(3.02);

	private static readonly ulong[] Zero = new ulong[10];

	private static ulong Nominal(int limb)
	{
		return limb % 2 is 0 ? 1UL << 26 : 1UL << 25;
	}

	private static ulong[] Scaled(double m)
	{
		return [.. Enumerable.Range(0, 10).Select(i => (ulong)Math.Floor(m * Nominal(i)))];
	}

	private static ulong[] EvenLimbs(ulong[] limbs)
	{
		return [.. limbs.Select(static (limb, i) => i % 2 is 0 ? limb : 0)];
	}

	private static ulong[] OddLimbs(ulong[] limbs)
	{
		return [.. limbs.Select(static (limb, i) => i % 2 is 0 ? 0 : limb)];
	}

	private static BigInteger ValueOfLimbs(ulong[] limbs)
	{
		BigInteger value = BigInteger.Zero;

		for (int i = 0; i < limbs.Length; ++i)
		{
			value += new BigInteger(limbs[i]) << LimbShifts[i];
		}

		return value;
	}

	// The ulong offset of limb i of lane j: in a vector of four lanes per limb, or, for Field25519x4Sse41, in a pair of ten two-lane vectors for lanes A and B followed by one for C and D.
	private static int Offset<TField>(int limb, int lane)
	{
		return typeof(TField) == typeof(Field25519x4Sse41) ? (lane >> 1) * 20 + limb * 2 + (lane & 1) : limb * 4 + lane;
	}

	private static TField FromLimbs<TField>(ulong[][] lanes, Func<int, int, int> offset, TField result = default) where TField : unmanaged
	{
		Span<ulong> words = MemoryMarshal.Cast<TField, ulong>(new Span<TField>(ref result));

		for (int lane = 0; lane < lanes.Length; ++lane)
		{
			for (int limb = 0; limb < 10; ++limb)
			{
				words[offset(limb, lane)] = lanes[lane][limb];
			}
		}

		return result;
	}

	private static ulong[] LimbsOf<TField>(TField value, Func<int, int, int> offset, int lane) where TField : unmanaged
	{
		ReadOnlySpan<ulong> words = MemoryMarshal.Cast<TField, ulong>(new ReadOnlySpan<TField>(in value));
		ulong[] limbs = new ulong[10];

		for (int limb = 0; limb < limbs.Length; ++limb)
		{
			limbs[limb] = words[offset(limb, lane)];
		}

		return limbs;
	}

	// Each lane of value against expected modulo p and, where bound is given, every limb at most that of bound.
	private static void CheckLimbs<TField>(List<string> failures, string operation, TField value, Func<int, int, int> offset, ulong[]? bound, params BigInteger[] expected) where TField : unmanaged
	{
		for (int lane = 0; lane < expected.Length; ++lane)
		{
			ulong[] limbs = LimbsOf(value, offset, lane);

			if (Mod(ValueOfLimbs(limbs)) != Mod(expected[lane]) || bound is not null && limbs.Where((limb, i) => limb > bound[i]).Any())
			{
				failures.Add($"{operation}, lane {lane}: [{string.Join(", ", limbs.Select(static limb => limb.ToString("X")))}], expected {Mod(expected[lane]):X}");
			}
		}
	}

	// Products of operands with the largest limbs that Multiply takes, then the point formulas from the largest limbs of a reduced value, in the lanes that offset places; otherOffset places otherLanes, if any, where they must not change the results.
	private static void RunBoundPointSteps<TField>(List<string> failures, Func<int, int, int> offset, ulong[][]? otherLanes = null, Func<int, int, int>? otherOffset = null) where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		ulong[][] lefts = [LeftMaximum, LeftMaximum, ReducedMaximum, EvenLimbs(LeftMaximum)];
		ulong[][] rights = [RightMaximum, ReducedMaximum, RightMaximum, OddLimbs(RightMaximum)];

		for (int rotation = 0; rotation < 4; ++rotation)
		{
			ulong[][] x = [.. lefts.Skip(rotation), .. lefts.Take(rotation)];
			ulong[][] y = [.. rights.Skip(rotation), .. rights.Take(rotation)];
			BigInteger[] l = [.. x.Select(ValueOfLimbs)];
			BigInteger[] r = [.. y.Select(ValueOfLimbs)];
			TField.Multiply(FromLanes(x), FromLanes(y), out TField product);
			CheckLimbs(failures, $"Multiply at the bounds, rotation {rotation}", product, offset, ReducedMaximum, l[0] * r[0], l[1] * r[1], l[2] * r[2], l[3] * r[3]);
		}

		ulong[][][] points = [[ReducedMaximum, ReducedMaximum, ReducedMaximum, ReducedMaximum], [ReducedMaximum, Zero, ReducedMaximum, Zero], [Zero, ReducedMaximum, Zero, ReducedMaximum], [EvenLimbs(ReducedMaximum), OddLimbs(ReducedMaximum), ReducedMaximum, Zero]];

		for (int k = 0; k < points.Length; ++k)
		{
			TField point = FromLanes(points[k]);
			BigInteger[] v = [.. points[k].Select(ValueOfLimbs)];
			BigInteger s1 = v[0] * v[0];
			BigInteger s2 = v[1] * v[1];
			BigInteger s5 = s1 + s2;
			BigInteger s6 = s1 - s2;
			BigInteger s8 = s6 + 2 * v[2] * v[2];
			BigInteger s9 = s5 - (v[0] + v[1]) * (v[0] + v[1]);
			TField.DoubleOperands(in point, out TField left, out TField right);
			CheckLimbs(failures, $"DoubleOperands {k}, left", left, offset, LeftMaximum, s8, s5, s8, s5);
			CheckLimbs(failures, $"DoubleOperands {k}, right", right, offset, RightMaximum, s9, s6, s6, s9);
			TField.Multiply(in left, in right, out TField product);
			CheckLimbs(failures, $"DoubleOperands {k}, product", product, offset, ReducedMaximum, s8 * s9, s5 * s6, s8 * s6, s5 * s9);

			ulong[][] cachedLanes = points[(k + 1) % points.Length];
			BigInteger[] c = [.. cachedLanes.Select(ValueOfLimbs)];
			BigInteger t8 = (v[1] - v[0]) * c[0];
			BigInteger t9 = (v[1] + v[0]) * c[1];
			BigInteger t10 = v[2] * c[2];
			BigInteger t11 = v[3] * c[3];
			BigInteger s12 = t9 - t8;
			BigInteger s13 = t9 + t8;
			BigInteger s14 = t10 - t11;
			BigInteger s15 = t10 + t11;
			TField.AddOperands(in point, FromLanes(cachedLanes), out left, out right);
			CheckLimbs(failures, $"AddOperands {k}, left", left, offset, LeftMaximum, s12, s15, s15, s12);
			CheckLimbs(failures, $"AddOperands {k}, right", right, offset, RightMaximum, s14, s13, s14, s13);
			TField.Multiply(in left, in right, out product);
			CheckLimbs(failures, $"AddOperands {k}, product", product, offset, ReducedMaximum, s12 * s14, s15 * s13, s15 * s14, s12 * s13);
		}

		TField FromLanes(ulong[][] lanes)
		{
			TField value = otherLanes is null ? default : FromLimbs<TField>(otherLanes, otherOffset!);
			return FromLimbs(lanes, offset, value);
		}
	}

	// The ladder steps and MultiplySmall from the largest limbs of a reduced value.
	private static void RunBoundLadderSteps<TField>(List<string> failures) where TField : unmanaged, IField25519x4<TField>
	{
		Func<int, int, int> offset = Offset<TField>;
		ulong[][][] states = [[ReducedMaximum, ReducedMaximum, ReducedMaximum, ReducedMaximum], [ReducedMaximum, Zero, Zero, ReducedMaximum], [EvenLimbs(ReducedMaximum), OddLimbs(ReducedMaximum), OddLimbs(ReducedMaximum), EvenLimbs(ReducedMaximum)]];
		TField[] multiplier = new TField[TField.MultiplierLength];
		TField.CreateMultiplier(in LargestTight, multiplier);
		BigInteger u = ValueOf(LargestTight);

		foreach (ulong[][] lanes in states)
		{
			TField state = FromLimbs<TField>(lanes, offset);
			BigInteger[] v = [.. lanes.Select(ValueOfLimbs)];

			foreach (ulong swap in (ulong[])[0, ulong.MaxValue])
			{
				BigInteger[] w = swap is 0 ? v : [v[2], v[3], v[0], v[1]];
				BigInteger a = w[0] + w[1];
				BigInteger b = w[0] - w[1];
				BigInteger aa = a * a;
				BigInteger bb = b * b;
				BigInteger e = aa - bb;
				BigInteger sum = (w[2] - w[3]) * a + (w[2] + w[3]) * b;
				BigInteger difference = (w[2] - w[3]) * a - (w[2] + w[3]) * b;
				BigInteger completed = aa + A24 * e;
				TField.LadderOperands(in state, swap, out TField left, out TField right);
				CheckLimbs(failures, $"LadderOperands, {swap:X}, left", left, offset, null, aa, e, sum, difference);
				CheckLimbs(failures, $"LadderOperands, {swap:X}, right", right, offset, null, bb, completed, sum, difference);
				TField.LadderProducts(in left, in right, in multiplier[0], out TField products);
				CheckLimbs(failures, $"LadderProducts, {swap:X}", products, offset, ReducedMaximum, aa * bb, e * completed, sum * sum, u * difference * difference);
			}

			TField.DiffSum(in state, out TField differences);
			TField.MultiplySmall(in differences, (1u << 18) - 1, (1u << 18) - 1, A24, 2 * 121666, out TField scaled);
			CheckLimbs(failures, "MultiplySmall of DiffSum", scaled, offset, ReducedMaximum, (v[1] - v[0]) * ((1 << 18) - 1), (v[1] + v[0]) * ((1 << 18) - 1), v[2] * A24, v[3] * 2 * 121666);
		}
	}

	private sealed class BoundSteps : IField25519x4Visitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IField25519x4<TField>
		{
			List<string> failures = [];
			RunBoundPointSteps<TField>(failures, Offset<TField>);
			RunBoundLadderSteps<TField>(failures);
			return failures;
		}
	}

	private sealed class RoundTrip : IField25519x4Visitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IField25519x4<TField>
		{
			List<string> failures = [];

			foreach (Field25519[] lanes in Lanes())
			{
				Check(failures, $"Create {Show(lanes)}", Extract(Create<TField>(lanes)), Values(lanes));
			}

			return failures;
		}
	}

	private sealed class Products : IField25519x4Visitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IField25519x4<TField>
		{
			List<string> failures = [];
			List<Field25519[]> all = Lanes();

			foreach (Field25519[] x in all)
			{
				TField left = Create<TField>(x);
				BigInteger[] l = Values(x);

				foreach (Field25519[] y in all)
				{
					TField right = Create<TField>(y);
					BigInteger[] r = Values(y);
					TField.Multiply(in left, in right, out TField product);
					Check(failures, $"Multiply {Show(x)}; {Show(y)}", Extract(product), l[0] * r[0], l[1] * r[1], l[2] * r[2], l[3] * r[3]);
				}

				TField.MultiplySmall(in left, 0, A24, 2 * 121666, (1u << 18) - 1, out TField scaled);
				Check(failures, $"MultiplySmall {Show(x)}", Extract(scaled), 0, l[1] * A24, l[2] * 2 * 121666, l[3] * ((1 << 18) - 1));
			}

			return failures;
		}
	}

	private sealed class PointSteps : IField25519x4Visitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IField25519x4<TField>
		{
			List<string> failures = [];
			List<Field25519[]> all = Lanes();

			for (int k = 0; k < all.Count; ++k)
			{
				RunPointSteps(failures, all, k, Create<TField>, Extract, NegateCached);
				Field25519[] lanes = all[k];
				string name = Show(lanes);
				TField point = Create<TField>(lanes);
				BigInteger[] v = Values(lanes);

				// Negations, the cached one also as a product's right operand.
				TField.NegateD(in point, out TField negated);
				Check(failures, $"NegateD {name}", Extract(negated), v[0], v[1], v[2], -v[3]);
				TField.NegateCached(in negated, out TField swapped);
				Check(failures, $"NegateCached of NegateD {name}", Extract(swapped), v[1], v[0], v[2], v[3]);
				TField.NegateCached(in point, out swapped);
				Check(failures, $"NegateCached {name}", Extract(swapped), v[1], v[0], v[2], -v[3]);
				TField.DiffSum(in point, out TField differences);
				Check(failures, $"DiffSum {name}", Extract(differences), v[1] - v[0], v[1] + v[0], v[2], v[3]);
				TField.Multiply(in differences, in swapped, out TField products);
				Check(failures, $"Multiply DiffSum {name}; NegateCached {name}", Extract(products), (v[1] - v[0]) * v[1], (v[1] + v[0]) * v[0], v[2] * v[2], -v[3] * v[3]);
			}

			return failures;
		}

		private static TField NegateCached<TField>(TField cached) where TField : unmanaged, IField25519x4<TField>
		{
			TField.NegateCached(in cached, out TField result);
			return result;
		}
	}

	private sealed class LadderSteps : IField25519x4Visitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IField25519x4<TField>
		{
			List<string> failures = [];
			List<Field25519[]> all = Lanes();

			foreach (Field25519[] lanes in all)
			{
				string name = Show(lanes);
				TField state = Create<TField>(lanes);
				BigInteger[] v = Values(lanes);

				foreach (ulong swap in (ulong[])[0, ulong.MaxValue])
				{
					BigInteger[] w = swap is 0 ? v : [v[2], v[3], v[0], v[1]];
					BigInteger a = w[0] + w[1];
					BigInteger b = w[0] - w[1];
					BigInteger c = w[2] + w[3];
					BigInteger d = w[2] - w[3];
					BigInteger aa = a * a;
					BigInteger bb = b * b;
					BigInteger e = aa - bb;
					BigInteger sum = d * a + c * b;
					BigInteger difference = d * a - c * b;
					BigInteger completed = aa + A24 * e;
					TField.LadderOperands(in state, swap, out TField left, out TField right);
					Check(failures, $"LadderOperands {name}, {swap:X}, left", Extract(left), aa, e, sum, difference);
					Check(failures, $"LadderOperands {name}, {swap:X}, right", Extract(right), bb, completed, sum, difference);

					// u at its bounds and of other kinds.
					foreach (Field25519[] multiplierLanes in all)
					{
						Field25519 u = multiplierLanes[3];
						TField[] multiplier = new TField[TField.MultiplierLength];
						TField.CreateMultiplier(in u, multiplier);
						TField.LadderProducts(in left, in right, in multiplier[0], out TField products);
						Check(failures, $"LadderProducts {name}, {swap:X}; {Field25519TestUtils.Show(in u)}", Extract(products), aa * bb, e * completed, sum * sum, ValueOf(u) * difference * difference);
					}

					TField swapped = state;
					TField.ConditionalSwapHalves(swap, ref swapped);
					Check(failures, $"ConditionalSwapHalves {name}, {swap:X}", Extract(swapped), w);
				}
			}

			return failures;
		}
	}
}
