using CryptoBase.EllipticCurves.Curve448;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.EllipticCurves.Curve448.Field448TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

// The bound states of 0, 1, limbs of 2^28 − 1 and the largest reduced limbs, combined, take the operands of the first and second products to their largest.
public class Field448x4Test
{
	private const int RandomCount = 6;

	private const ulong Nominal = 1UL << 28;

	private static readonly ulong[] ExtractBound = [.. Enumerable.Range(0, 8).Select(static i => i % 4 is 0 ? (1UL << 56) + 31 : (1UL << 56) - 1)];

	private static readonly ulong[] ReducedMaximum = [.. Enumerable.Repeat(Nominal + (1UL << 9) - 1, 16)];

	private static readonly ulong[] ProductMaximum = [.. Enumerable.Range(0, 16).Select(static i => i switch { 1 => Nominal + (1UL << 8) - 1, 9 => Nominal + (1UL << 9) - 1, _ => Nominal - 1 })];

	private static readonly ulong[] Zero = new ulong[16];

	private static readonly ulong[] One = [1, .. new ulong[15]];

	// A product by 1 leaves these limbs as they are.
	private static readonly ulong[] Full = [.. Enumerable.Repeat(Nominal - 1, 16)];

	private static readonly Field448 Largest = Limbs([.. Enumerable.Repeat((1UL << 57) - 1, 8)]);

	private static readonly (int Comb, uint Index, ulong Negative)[] Entries = [(0, 0, 0), (0, 0, ulong.MaxValue), (14, 31, ulong.MaxValue), (14, 31, 0), (7, 13, ulong.MaxValue), (3, 30, 0)];

	[Test]
	public async Task EveryFieldIsListed()
	{
		Type[] implementations = typeof(IField448x4<>).Assembly.GetTypes().Where(static type => type is { IsInterface: false, IsAbstract: false } && type.GetInterfaces().Any(static i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IField448x4<>))).ToArray();

		await Assert.That(Field448VectorCase.All().Select(static field => field.FieldType)).IsEquivalentTo(implementations);
	}

	[Test]
	[MethodDataSource(typeof(Field448VectorCase), nameof(Field448VectorCase.All))]
	public async Task CreateAndExtractKeepTheLanes(Field448VectorCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new RoundTrip())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field448VectorCase), nameof(Field448VectorCase.All))]
	public async Task LadderStepsMatchBigInteger(Field448VectorCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new LadderSteps(atBounds: false))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field448VectorCase), nameof(Field448VectorCase.All))]
	public async Task LadderStepsAtTheirBoundsMatchBigInteger(Field448VectorCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new LadderSteps(atBounds: true))).IsEmpty();
	}

	// The formulas are polynomials, so they hold for lanes that are not points.
	[Test]
	[MethodDataSource(typeof(Field448VectorCase), nameof(Field448VectorCase.All))]
	public async Task TwistedStepsMatchBigInteger(Field448VectorCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new TwistedSteps(atBounds: false))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field448VectorCase), nameof(Field448VectorCase.All))]
	public async Task TwistedStepsAtTheirBoundsMatchBigInteger(Field448VectorCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new TwistedSteps(atBounds: true))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field448VectorCase), nameof(Field448VectorCase.All))]
	public async Task EdwardsStepsMatchBigInteger(Field448VectorCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new EdwardsSteps(atBounds: false))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Field448VectorCase), nameof(Field448VectorCase.All))]
	public async Task EdwardsStepsAtTheirBoundsMatchBigInteger(Field448VectorCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new EdwardsSteps(atBounds: true))).IsEmpty();
	}

	private static List<Field448[]> Lanes()
	{
		Random random = new(7);
		List<Field448> values = [Largest, Split((BigInteger.One << 448) - 1), Split(P - 1), Split(P), Split(P + 1), Split(0), Split(1), Split(BigInteger.One << 224), Split(P - (BigInteger.One << 224))];

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(Split(RandomBelow(random, BigInteger.One << 448)));
			values.Add(Limbs([.. Enumerable.Range(0, 8).Select(_ => (ulong)random.NextInt64() & (1UL << 57) - 1)]));
		}

		List<Field448[]> lanes = [[Largest, Largest, Largest, Largest], [values[5], values[5], values[5], values[5]]];

		for (int i = 0; i < values.Count; ++i)
		{
			lanes.Add([values[i], values[(i + 1) % values.Count], values[(i + 3) % values.Count], values[(i + 7) % values.Count]]);
		}

		return lanes;
	}

	private static List<(string Name, TField State, BigInteger[] Values)> States<TField>(bool atBounds) where TField : unmanaged, IField448x4<TField>
	{
		List<(string Name, TField State, BigInteger[] Values)> states = [];

		if (!atBounds)
		{
			foreach (Field448[] lanes in Lanes())
			{
				states.Add((Show(lanes), Create<TField>(lanes), Values(lanes)));
			}

			return states;
		}

		(string Name, ulong[] Limbs)[] kinds = [("0", Zero), ("1", One), ("2^28 − 1", Full), ("reduced maximum", ReducedMaximum)];

		for (int k = 0; k < 1 << 8; ++k)
		{
			(string Name, ulong[] Limbs)[] lanes = [kinds[k & 3], kinds[k >> 2 & 3], kinds[k >> 4 & 3], kinds[k >> 6]];
			ulong[][] limbs = [.. lanes.Select(static lane => lane.Limbs)];
			states.Add(($"({string.Join(", ", lanes.Select(static lane => lane.Name))})", FromRaw<TField>(limbs), [.. limbs.Select(ValueOfRaw)]));
		}

		ulong[][] alternate = [EvenLimbs(ReducedMaximum), OddLimbs(ReducedMaximum), OddLimbs(ReducedMaximum), EvenLimbs(ReducedMaximum)];
		states.Add(("alternate limbs at the reduced maximum", FromRaw<TField>(alternate), [.. alternate.Select(ValueOfRaw)]));
		return states;
	}

	private static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		byte[] bytes = new byte[bound.GetByteCount(isUnsigned: true) + 8];
		random.NextBytes(bytes);
		return new BigInteger(bytes, isUnsigned: true) % bound;
	}

	private static BigInteger[] Values(Field448[] lanes)
	{
		return [.. lanes.Select(static lane => ValueOf(in lane))];
	}

	private static string Show(Field448[] lanes)
	{
		return string.Join(", ", lanes.Select(static lane => string.Join(":", LimbsOf(in lane).Select(static limb => limb.ToString("X")))));
	}

	private static TField Create<TField>(Field448[] lanes) where TField : unmanaged, IField448x4<TField>
	{
		TField.Create(in lanes[0], in lanes[1], in lanes[2], in lanes[3], out TField result);
		return result;
	}

	private static Field448[] Extract<TField>(TField value) where TField : unmanaged, IField448x4<TField>
	{
		TField.Extract(in value, out Field448 a, out Field448 b, out Field448 c, out Field448 d);
		return [a, b, c, d];
	}

	private static void Check<TField>(List<string> failures, string operation, TField value, ulong[]? bound, params BigInteger[] expected) where TField : unmanaged, IField448x4<TField>
	{
		Field448[] lanes = Extract(value);

		for (int lane = 0; lane < expected.Length; ++lane)
		{
			ulong[] limbs = RawLimbs(value, lane);

			if (Mod(ValueOf(in lanes[lane])) != Mod(expected[lane]) || !IsWithin(in lanes[lane], ExtractBound) || Mod(ValueOfRaw(limbs)) != Mod(expected[lane]) || bound is not null && limbs.Where((limb, i) => limb > bound[i]).Any())
			{
				failures.Add($"{operation}, lane {lane}: [{string.Join(", ", limbs.Select(static limb => limb.ToString("X")))}], expected {Mod(expected[lane]):X}");
			}
		}
	}

	private static (int Size, Func<int, int, int> Offset) Layout<TField>()
	{
		if (typeof(TField) == typeof(Field448x4Avx2))
		{
			return (sizeof(ulong), static (limb, lane) => limb * 4 + lane);
		}

		// Limbs k and k + 8 share vector k, in its low and high halves.
		if (typeof(TField) == typeof(Field448x4Avx512))
		{
			return (sizeof(ulong), static (limb, lane) => (limb & 7) * 8 + (limb >> 3) * 4 + lane);
		}

		if (typeof(TField) == typeof(Field448x4AdvSimd))
		{
			return (sizeof(uint), static (limb, lane) => limb * 4 + lane);
		}

		// Lanes A and B in one pair of sixteen vectors and C and D in the next.
		if (typeof(TField) == typeof(Field448x4Sse41))
		{
			return (sizeof(ulong), static (limb, lane) => (lane >> 1) * 32 + limb * 2 + (lane & 1));
		}

		throw new NotSupportedException($"{typeof(TField).Name} has no layout here.");
	}

	private static TField FromRaw<TField>(ulong[][] lanes) where TField : unmanaged
	{
		TField value = default;
		Span<byte> bytes = MemoryMarshal.AsBytes(new Span<TField>(ref value));
		(int size, Func<int, int, int> offset) = Layout<TField>();

		for (int lane = 0; lane < lanes.Length; ++lane)
		{
			for (int limb = 0; limb < 16; ++limb)
			{
				Span<byte> destination = bytes.Slice(offset(limb, lane) * size, size);

				if (size is sizeof(uint))
				{
					MemoryMarshal.Write(destination, checked((uint)lanes[lane][limb]));
				}
				else
				{
					MemoryMarshal.Write(destination, lanes[lane][limb]);
				}
			}
		}

		return value;
	}

	private static ulong[] RawLimbs<TField>(TField value, int lane) where TField : unmanaged
	{
		ReadOnlySpan<byte> bytes = MemoryMarshal.AsBytes(new ReadOnlySpan<TField>(in value));
		(int size, Func<int, int, int> offset) = Layout<TField>();
		ulong[] limbs = new ulong[16];

		for (int limb = 0; limb < limbs.Length; ++limb)
		{
			ReadOnlySpan<byte> source = bytes.Slice(offset(limb, lane) * size, size);
			limbs[limb] = size is sizeof(uint) ? MemoryMarshal.Read<uint>(source) : MemoryMarshal.Read<ulong>(source);
		}

		return limbs;
	}

	private static BigInteger ValueOfRaw(ulong[] limbs)
	{
		BigInteger value = BigInteger.Zero;

		for (int i = limbs.Length - 1; i >= 0; --i)
		{
			value = (value << 28) + limbs[i];
		}

		return value;
	}

	private static ulong[] EvenLimbs(ulong[] limbs)
	{
		return [.. limbs.Select(static (limb, i) => i % 2 is 0 ? limb : 0)];
	}

	private static ulong[] OddLimbs(ulong[] limbs)
	{
		return [.. limbs.Select(static (limb, i) => i % 2 is 0 ? 0 : limb)];
	}

	private static BigInteger[] Step(BigInteger[] state, ulong swap, BigInteger u)
	{
		return LadderStep(swap is 0 ? state : [state[2], state[3], state[0], state[1]], u);
	}

	private static void RunStep<TField>(List<string> failures, string name, TField state, BigInteger[] values, Field448 u) where TField : unmanaged, IField448x4<TField>
	{
		TField[] multiplier = new TField[TField.MultiplierLength];
		TField[] scratch = new TField[TField.ScratchLength];
		TField.CreateMultiplier(in u, multiplier);

		foreach (ulong swap in (ulong[])[0, ulong.MaxValue])
		{
			TField next = state;
			TField.LadderStep(ref next, swap, in multiplier[0], ref scratch[0]);
			Check(failures, $"LadderStep {name}, {swap:X}", next, ReducedMaximum, Step(values, swap, ValueOf(in u)));
			TField swapped = state;
			TField.ConditionalSwapHalves(swap, ref swapped);
			Check(failures, $"ConditionalSwapHalves {name}, {swap:X}", swapped, null, swap is 0 ? values : [values[2], values[3], values[0], values[1]]);
		}
	}

	// Coordinates of 0, 1 or the largest tight limbs make each first-round product of Add 0, a lane of the point or its largest.
	private static EdwardsAffinePoint[] AffinePoints()
	{
		Field448[] coordinates = [Split(0), Split(1), LargestTight];
		List<EdwardsAffinePoint> points = [EdwardsVariableTimeBaseTable.Entries[1]];

		foreach (Field448 x in coordinates)
		{
			foreach (Field448 y in coordinates)
			{
				foreach (Field448 product in coordinates)
				{
					points.Add(new EdwardsAffinePoint { X = x, Y = y, DXY = product });
				}
			}
		}

		return [.. points];
	}

	private static (BigInteger, BigInteger, BigInteger, BigInteger) Squares(BigInteger[] point)
	{
		BigInteger sum = point[0] + point[1];
		return (point[0] * point[0], point[1] * point[1], point[2] * point[2], sum * sum);
	}

	private sealed class RoundTrip : IField448VectorVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IEdwardsField448x4<TField>
		{
			List<string> failures = [];

			foreach (Field448[] lanes in Lanes())
			{
				Check(failures, $"Create {Show(lanes)}", Create<TField>(lanes), ReducedMaximum, Values(lanes));
			}

			return failures;
		}
	}

	private sealed class LadderSteps(bool atBounds) : IField448VectorVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IEdwardsField448x4<TField>
		{
			List<string> failures = [];
			List<(string Name, TField State, BigInteger[] Values)> states = States<TField>(atBounds);
			List<Field448[]> all = Lanes();

			for (int k = 0; k < states.Count; ++k)
			{
				(string name, TField state, BigInteger[] values) = states[k];
				RunStep(failures, name, state, values, atBounds ? Largest : all[(k + 5) % all.Count][3]);
			}

			return failures;
		}
	}

	private sealed class TwistedSteps(bool atBounds) : IField448VectorVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IEdwardsField448x4<TField>
		{
			List<string> failures = [];
			TField[] scratch = new TField[TField.ScratchLength];

			foreach ((string name, TField state, BigInteger[] values) in States<TField>(atBounds))
			{
				TField doubled = state;
				TField.TwistedDouble(ref doubled, ref scratch[0]);
				Check(failures, $"TwistedDouble {name}", doubled, ProductMaximum, TwistedDouble(values));

				foreach ((int comb, uint index, ulong negative) in Entries)
				{
					TwistedBaseTable.Select(comb, index, 0, out TwistedNielsPoint entry);
					TField sum = state;
					TField.SelectBase(comb, index, negative, ref scratch[0]);
					TField.TwistedAdd(ref sum, ref scratch[0]);
					Check(failures, $"TwistedAdd {name}, entry {index} of comb {comb}, {negative:X}", sum, ProductMaximum, TwistedAdd(values, in entry, negative is not 0));
				}
			}

			return failures;
		}

		private static BigInteger[] TwistedDouble(BigInteger[] point)
		{
			(BigInteger xx, BigInteger yy, BigInteger zz, BigInteger ss) = Squares(point);
			BigInteger e = ss - xx - yy;
			BigInteger g = yy - xx;
			BigInteger f = 2 * zz + xx - yy;
			BigInteger h = xx + yy;
			return [e * f, g * h, f * g, e * h];
		}

		private static BigInteger[] TwistedAdd(BigInteger[] point, in TwistedNielsPoint entry, bool negative)
		{
			BigInteger plus = ValueOf(in entry.YPlusX);
			BigInteger minus = ValueOf(in entry.YMinusX);
			BigInteger product = ValueOf(in entry.TwoDXY);
			(BigInteger e0, BigInteger e1, BigInteger e3) = negative ? (plus, minus, -product) : (minus, plus, product);
			BigInteger p0 = (point[0] - point[1]) * e0;
			BigInteger p1 = (point[0] + point[1]) * e1;
			BigInteger p2 = point[2] * 2;
			BigInteger p3 = point[3] * e3;
			BigInteger e = p1 + p0;
			BigInteger h = p1 - p0;
			BigInteger f = p2 - p3;
			BigInteger g = p2 + p3;
			return [e * f, g * h, f * g, e * h];
		}
	}

	private sealed class EdwardsSteps(bool atBounds) : IField448VectorVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, IEdwardsField448x4<TField>
		{
			List<string> failures = [];
			EdwardsAffinePoint[] affine = AffinePoints();
			TField[] scratch = new TField[TField.ScratchLength];

			foreach ((string name, TField state, BigInteger[] values) in States<TField>(atBounds))
			{
				TField doubled = state;
				TField.Double(ref doubled, ref scratch[0]);
				Check(failures, $"Double {name}", doubled, ProductMaximum, Double(values));

				for (int i = 0; i < affine.Length; ++i)
				{
					foreach (bool negative in (bool[])[false, true])
					{
						TField sum = state;
						TField.LoadAffine(in affine[i], negative, ref scratch[0]);
						TField.Add(ref sum, ref scratch[0]);
						Check(failures, $"Add {name}, affine point {i}, negated: {negative}", sum, ProductMaximum, Add(values, in affine[i], negative));
					}
				}
			}

			return failures;
		}

		private static BigInteger[] Double(BigInteger[] point)
		{
			(BigInteger xx, BigInteger yy, BigInteger zz, BigInteger ss) = Squares(point);
			BigInteger x = ss - xx - yy;
			BigInteger y = yy - xx;
			BigInteger s = xx + yy;
			BigInteger t = 2 * zz - xx - yy;
			return [x * t, y * s, s * t, x * y];
		}

		private static BigInteger[] Add(BigInteger[] point, in EdwardsAffinePoint affine, bool negative)
		{
			BigInteger x = ValueOf(in affine.X);
			BigInteger y = ValueOf(in affine.Y);
			BigInteger product = ValueOf(in affine.DXY);

			if (negative)
			{
				x = -x;
				product = -product;
			}

			BigInteger a = point[0] * x;
			BigInteger b = point[1] * y;
			BigInteger c = point[3] * product;
			BigInteger s = (point[0] + point[1]) * (x + y);
			BigInteger e = s - a - b;
			BigInteger f = point[2] - c;
			BigInteger g = point[2] + c;
			BigInteger h = b - a;
			return [e * f, g * h, f * g, e * h];
		}
	}
}
