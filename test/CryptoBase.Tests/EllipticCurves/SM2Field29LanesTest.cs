using CryptoBase.EllipticCurves;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves;

// The lane fields of radix 2^29 against BigInteger, lane by lane, with inputs at the bounds that SM2Field29 states for each member: a product takes limbs up to 2^30 + 2^8 − 1 on both sides, or up to 7·2^29 − 1 against limbs up to those of a product, a subtrahend limbs up to those of the 4p that Subtract adds, Reduce limbs 0 to 7 up to 2^32 − 1 and limb 8 up to 2^36 − 1, and Halve limbs up to 2^62. The limbs are those of the lanes as they lie in memory, limb k of lane i at k·LaneCount + i.
public class SM2Field29LanesTest
{
	private const int LimbCount = 9;

	private const int RandomCount = 8;

	private const ulong Nominal = 1UL << 29;

	private const ulong ProductInput = (1UL << 30) + (1UL << 8) - 1;

	// The largest limb of a product, limbs 2 to 7 below 2^29 + 65, and the largest left limb against it.
	private const ulong ProductLimb = Nominal + 64;

	private const ulong WideInput = (7UL << 29) - 1;

	private static readonly BigInteger P = (BigInteger.One << 256) - (BigInteger.One << 224) - (BigInteger.One << 96) + (BigInteger.One << 64) - 1;

	private static readonly BigInteger R = BigInteger.One << 261;

	private static readonly BigInteger RInverse = BigInteger.ModPow(R, P - 2, P);

	// The limbs of the 4p of Subtract and ConditionalNegate, the largest subtrahends they take.
	private static readonly ulong[] FourP = [0x3FFFFFFC, 0x3FFFFFFE, 0x200000FE, 0x3FFFF7FF, 0x3FFFFFFE, 0x3FFFFFFE, 0x3FFFFFFE, 0x3F7FFFFE, 0x3FFFFFE];

	[Test]
	public async Task EveryFieldIsListed()
	{
		Type[] implementations = typeof(ISM2Field29Lanes<>).Assembly.GetTypes().Where(static type => type is { IsInterface: false, IsAbstract: false } && type.GetInterfaces().Any(static i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ISM2Field29Lanes<>))).ToArray();

		await Assert.That(SM2Field29LanesCase.All().Select(static field => field.FieldType)).IsEquivalentTo(implementations);
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task ProductsMatchBigInteger(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new Products())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task WideProductsMatchBigInteger(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new WideProducts())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task SumsAndDifferencesMatchBigInteger(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new SumsAndDifferences())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task ReduceMatchesBigInteger(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new Reductions())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task MasksAndMovesKeepTheLanes(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new MasksAndMoves())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task HalveMatchesBigInteger(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new Halves())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task ConversionsKeepTheValues(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new Conversions())).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM2Field29LanesCase), nameof(SM2Field29LanesCase.All))]
	public async Task PacksGiveTheCanonicalValues(SM2Field29LanesCase field)
	{
		SkipUnlessSupported(field);
		await Assert.That(field.Accept(new Packs())).IsEmpty();
	}

	// Lane values, in limbs: 0, 1, limbs of 2^29 − 1 and of the largest, p − 1, p and 2p in their own limbs, 1 at limb 0 with the rest 0, whose products with full limbs have small columns and the largest q of each round, and random limbs below 2^29 to 2^32, none above the largest.
	private static List<ulong[]> Values(int seed, ulong largest)
	{
		Random random = new(seed);
		List<ulong[]> values = [new ulong[LimbCount], Split(1), Repeat(Nominal - 1), Repeat(largest), Split(P - 1), Split(P), Split(2 * P), Split(R % P)];

		for (int i = 0; i < RandomCount; ++i)
		{
			int bits = 29 + i % 4;
			values.Add([.. Enumerable.Range(0, LimbCount).Select(_ => Math.Min((ulong)random.NextInt64() & (1UL << bits) - 1, largest))]);
			values.Add(Split(RandomBelow(random, P)));
		}

		return values;
	}

	// The values in lanes, each lane taking its own one in turn.
	private static List<ulong[][]> Lanes(int laneCount, List<ulong[]> values, int shift)
	{
		List<ulong[][]> lanes = [];

		foreach (int i in Enumerable.Range(0, values.Count))
		{
			lanes.Add([.. Enumerable.Range(0, laneCount).Select(lane => values[(i + lane * shift) % values.Count])]);
		}

		return lanes;
	}

	private static ulong[] Repeat(ulong limb)
	{
		return [.. Enumerable.Repeat(limb, LimbCount)];
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

	private static BigInteger ValueOf(ulong[] limbs)
	{
		BigInteger value = 0;

		for (int i = LimbCount - 1; i >= 0; --i)
		{
			value = (value << 29) + limbs[i];
		}

		return value;
	}

	private static BigInteger Mod(BigInteger value)
	{
		BigInteger remainder = value % P;
		return remainder.Sign < 0 ? remainder + P : remainder;
	}

	private static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		byte[] bytes = new byte[bound.GetByteCount(isUnsigned: true) + 8];
		random.NextBytes(bytes);
		return new BigInteger(bytes, isUnsigned: true) % bound;
	}

	private static TField FromLanes<TField>(ulong[][] lanes) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		TField value = default;
		Span<ulong> limbs = MemoryMarshal.Cast<TField, ulong>(new Span<TField>(ref value));

		for (int lane = 0; lane < lanes.Length; ++lane)
		{
			for (int limb = 0; limb < LimbCount; ++limb)
			{
				limbs[limb * TField.LaneCount + lane] = lanes[lane][limb];
			}
		}

		return value;
	}

	private static ulong[] LaneLimbs<TField>(in TField value, int lane) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		ReadOnlySpan<ulong> limbs = MemoryMarshal.Cast<TField, ulong>(new ReadOnlySpan<TField>(in value));
		ulong[] result = new ulong[LimbCount];

		for (int limb = 0; limb < LimbCount; ++limb)
		{
			result[limb] = limbs[limb * TField.LaneCount + lane];
		}

		return result;
	}

	private static string Show(ulong[] limbs)
	{
		return string.Join(":", limbs.Select(static limb => limb.ToString("X")));
	}

	// A Montgomery product: x·y/2^261 mod p, limbs 0 and 1 below 2^29, limbs 2 to 7 below 2^29 + 65, and a value below x·y/2^261 + p + 2^226.
	private static void CheckProduct<TField>(List<string> failures, string operation, in TField result, ulong[][] left, ulong[][] right) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		for (int lane = 0; lane < left.Length; ++lane)
		{
			ulong[] limbs = LaneLimbs(in result, lane);
			BigInteger x = ValueOf(left[lane]);
			BigInteger y = ValueOf(right[lane]);
			BigInteger value = ValueOf(limbs);

			if (Mod(value - x * y * RInverse) != 0 || value >= x * y / R + P + (BigInteger.One << 226) || limbs[0] >= Nominal || limbs[1] >= Nominal || limbs.Skip(2).Take(6).Any(static limb => limb > ProductLimb))
			{
				failures.Add($"{operation} {Show(left[lane])}, {Show(right[lane])}, lane {lane}: {Show(limbs)}");
			}
		}
	}

	// A product of MultiplyRipple or SquareRipple: the value of the product of Multiply or Square, with limbs 0 to 7 below 2^29.
	private static void CheckRipple<TField>(List<string> failures, string operation, in TField ripple, in TField product, int lanes) where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		for (int lane = 0; lane < lanes; ++lane)
		{
			ulong[] limbs = LaneLimbs(in ripple, lane);

			if (ValueOf(limbs) != ValueOf(LaneLimbs(in product, lane)) || limbs.Take(8).Any(static limb => limb >= Nominal))
			{
				failures.Add($"{operation}, lane {lane}: {Show(limbs)}");
			}
		}
	}

	// Products and squares of every pair of values, each a full value or the value of a lane at its largest limbs, by both carries.
	private sealed class Products : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			List<ulong[]> values = Values(1, ProductInput);
			List<ulong[][]> lefts = Lanes(TField.LaneCount, values, 1);
			List<ulong[][]> rights = Lanes(TField.LaneCount, values, 3);

			foreach (ulong[][] left in lefts)
			{
				TField x = FromLanes<TField>(left);
				TField.Square(in x, out TField square);
				TField.SquareRipple(in x, out TField rippleSquare);
				CheckProduct(failures, "Square", square, left, left);
				CheckRipple(failures, "SquareRipple", rippleSquare, square, left.Length);

				foreach (ulong[][] right in rights)
				{
					TField y = FromLanes<TField>(right);
					TField.Multiply(in x, in y, out TField product);
					CheckProduct(failures, "Multiply", product, left, right);
					TField.MultiplyRipple(in x, in y, out TField ripple);
					CheckRipple(failures, "MultiplyRipple", ripple, product, left.Length);
				}
			}

			return failures;
		}
	}

	// Limbs up to 7·2^29 − 1 against limbs up to 2^29 + 64, on either side.
	private sealed class WideProducts : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			Random random = new(6);
			List<ulong[]> wide = Values(6, WideInput);
			List<ulong[]> narrow = [Repeat(ProductLimb), Split(P), Split(2 * P), [.. Repeat(Nominal - 1).Take(2), .. Repeat(ProductLimb).Skip(2)]];

			for (int i = 0; i < RandomCount; ++i)
			{
				narrow.Add([.. Enumerable.Range(0, LimbCount).Select(_ => (ulong)random.NextInt64((long)ProductLimb + 1))]);
			}

			foreach (ulong[][] left in Lanes(TField.LaneCount, wide, 1))
			{
				TField x = FromLanes<TField>(left);

				foreach (ulong[][] right in Lanes(TField.LaneCount, narrow, 1))
				{
					TField y = FromLanes<TField>(right);
					TField.Multiply(in x, in y, out TField product);
					CheckProduct(failures, "Multiply wide by narrow", product, left, right);
					TField.MultiplyRipple(in x, in y, out TField ripple);
					CheckRipple(failures, "MultiplyRipple wide by narrow", ripple, product, left.Length);
					TField.Multiply(in y, in x, out product);
					CheckProduct(failures, "Multiply narrow by wide", product, right, left);
					TField.MultiplyRipple(in y, in x, out ripple);
					CheckRipple(failures, "MultiplyRipple narrow by wide", ripple, product, left.Length);
				}
			}

			return failures;
		}
	}

	// Add adds limbs; Subtract leaves left + 4p − right, no limb negative, for subtrahends up to the limbs of that 4p.
	private sealed class SumsAndDifferences : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			List<ulong[]> values = Values(2, ProductInput);
			List<ulong[]> subtrahends = [FourP, new ulong[LimbCount], Split(P - 1), Split(2 * P - 1), [.. Repeat(Nominal - 1).Take(8), (1UL << 26) - 2], [.. Repeat(ProductLimb).Take(8), 0]];

			foreach (ulong[][] left in Lanes(TField.LaneCount, values, 1))
			{
				foreach (ulong[][] right in Lanes(TField.LaneCount, subtrahends, 1))
				{
					TField x = FromLanes<TField>(left);
					TField y = FromLanes<TField>(right);
					TField.Add(in x, in y, out TField sum);
					TField.Subtract(in x, in y, out TField difference);

					for (int lane = 0; lane < left.Length; ++lane)
					{
						ulong[] sumLimbs = LaneLimbs(in sum, lane);
						ulong[] differenceLimbs = LaneLimbs(in difference, lane);

						if (!sumLimbs.SequenceEqual(left[lane].Zip(right[lane], static (a, b) => a + b)))
						{
							failures.Add($"Add {Show(left[lane])}, {Show(right[lane])}, lane {lane}: {Show(sumLimbs)}");
						}

						if (!differenceLimbs.SequenceEqual(left[lane].Zip(right[lane], FourP).Select(static limbs => limbs.First + limbs.Third - limbs.Second)) || Mod(ValueOf(differenceLimbs) - ValueOf(left[lane]) + ValueOf(right[lane])) != 0 || differenceLimbs.Any(static limb => limb >= 1UL << 63))
						{
							failures.Add($"Subtract {Show(left[lane])}, {Show(right[lane])}, lane {lane}: {Show(differenceLimbs)}");
						}
					}
				}
			}

			return failures;
		}
	}

	// For limbs 0 to 7 below 2^32 and limb 8 below 2^36, Reduce gives limbs 0 to 7 below 2^29, limb 8 below 2^24 + 2^5 and a value below 2p. Every limb at its most takes h and the carries to their largest.
	private sealed class Reductions : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			ulong most = (1UL << 32) - 1;
			ulong top = (1UL << 36) - 1;
			Random random = new(3);
			List<ulong[]> values = [[.. Repeat(most).Take(8), top], [.. new ulong[8], top], [.. Repeat(most).Take(8), 0], new ulong[LimbCount], Split(P), Split(2 * P - 1), [.. new ulong[8], 1UL << 24], FourP];

			for (int i = 0; i < 4 * RandomCount; ++i)
			{
				values.Add([.. Enumerable.Range(0, LimbCount).Select(limb => (ulong)random.NextInt64() & (limb < 8 ? most : top))]);
			}

			foreach (ulong[][] lanes in Lanes(TField.LaneCount, values, 1))
			{
				TField value = FromLanes<TField>(lanes);
				TField.Reduce(in value, out TField reduced);

				for (int lane = 0; lane < lanes.Length; ++lane)
				{
					ulong[] limbs = LaneLimbs(in reduced, lane);
					BigInteger result = ValueOf(limbs);

					if (Mod(result - ValueOf(lanes[lane])) != 0 || result >= 2 * P || limbs.Take(8).Any(static limb => limb >= Nominal) || limbs[8] >= (1UL << 24) + (1UL << 5))
					{
						failures.Add($"Reduce {Show(lanes[lane])}, lane {lane}: {Show(limbs)}");
					}
				}
			}

			return failures;
		}
	}

	// ConditionalSelect and ConditionalNegate by masks that differ from lane to lane, and MoveDown by every distance below LaneCount, which the folds of SM2Vector read in the lanes below the distance.
	private sealed class MasksAndMoves : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			int laneCount = TField.LaneCount;
			List<ulong[]> values = [Split(0), Split(1), Split(P - 1), Split(2 * P - 1), [.. Repeat(Nominal - 1).Take(8), (1UL << 25) - 1], FourP, Split(R % P)];
			Random random = new(4);

			for (int i = 0; i < RandomCount; ++i)
			{
				values.Add(Split(RandomBelow(random, 2 * P)));
			}

			List<ulong[][]> lanes = Lanes(laneCount, values, 1);

			for (int i = 0; i < lanes.Count; ++i)
			{
				ulong[][] whenSet = lanes[i];
				ulong[][] whenClear = lanes[(i + 1) % lanes.Count];
				ulong[] mask = [.. Enumerable.Range(i, laneCount).Select(static k => k % 3 is 0 ? ulong.MaxValue : 0)];
				TField set = FromLanes<TField>(whenSet);
				TField clear = FromLanes<TField>(whenClear);
				TField.ConditionalSelect(in mask[0], in set, in clear, out TField selected);
				TField negated = set;
				TField.ConditionalNegate(in mask[0], ref negated);

				for (int lane = 0; lane < laneCount; ++lane)
				{
					bool isSet = mask[lane] is not 0;
					ulong[] selectedLimbs = LaneLimbs(in selected, lane);
					ulong[] negatedLimbs = LaneLimbs(in negated, lane);

					if (!selectedLimbs.SequenceEqual(isSet ? whenSet[lane] : whenClear[lane]))
					{
						failures.Add($"ConditionalSelect lane {lane}: {Show(selectedLimbs)}");
					}

					ulong[] expected = isSet ? [.. FourP.Zip(whenSet[lane], static (a, b) => a - b)] : whenSet[lane];

					if (!negatedLimbs.SequenceEqual(expected) || isSet && (Mod(ValueOf(negatedLimbs) + ValueOf(whenSet[lane])) != 0 || ValueOf(negatedLimbs) > 4 * P || negatedLimbs.Any(static limb => limb >= 2 * Nominal)))
					{
						failures.Add($"ConditionalNegate {Show(whenSet[lane])}, lane {lane}: {Show(negatedLimbs)}");
					}
				}

				for (int distance = 1; distance < laneCount; distance *= 2)
				{
					TField.MoveDown(in set, distance, out TField moved);

					for (int lane = 0; lane < distance; ++lane)
					{
						if (!LaneLimbs(in moved, lane).SequenceEqual(whenSet[lane + distance]))
						{
							failures.Add($"MoveDown {distance}, lane {lane}: {Show(LaneLimbs(in moved, lane))}");
						}
					}
				}
			}

			return failures;
		}
	}

	// value/2 mod p, exactly (value + p)/2 for an odd value, for limbs up to 2^62 and every limb at its most, limb i below (L_i + p_i)/2 + 2^28.
	private sealed class Halves : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			ulong most = (1UL << 62) - 1;
			ulong[] p = Split(P);
			Random random = new(7);
			List<ulong[]> values = [Repeat(most), [.. Repeat(most).Take(8), most - 1], Split(1), Split(P), Split(2 * P - 1), Split(2 * P - 2), new ulong[LimbCount], FourP];

			for (int i = 0; i < 4 * RandomCount; ++i)
			{
				int bits = 29 + i % 34;
				values.Add([.. Enumerable.Range(0, LimbCount).Select(_ => (ulong)random.NextInt64() & (1UL << bits) - 1)]);
			}

			foreach (ulong[][] lanes in Lanes(TField.LaneCount, values, 1))
			{
				TField value = FromLanes<TField>(lanes);
				TField.Halve(in value, out TField half);

				for (int lane = 0; lane < lanes.Length; ++lane)
				{
					ulong[] limbs = LaneLimbs(in half, lane);
					BigInteger v = ValueOf(lanes[lane]);
					bool odd = (lanes[lane][0] & 1) is not 0;
					BigInteger expected = (v + (odd ? P : 0)) / 2;
					bool bounded = limbs.Select((limb, i) => (BigInteger)limb < ((BigInteger)lanes[lane][i] + (odd ? p[i] : 0)) / 2 + (1UL << 28) + 1).All(static inside => inside);

					if (ValueOf(limbs) != expected || !bounded)
					{
						failures.Add($"Halve {Show(lanes[lane])}, lane {lane}: {Show(limbs)}");
					}
				}
			}

			return failures;
		}
	}

	// One in every lane; LoadEntries takes points as SM2Field52.Pack writes them, lane i from point i, and doubles them for R = 2^261, which Halve and Reduce take back; SM2Field29.ToField52 joins lane 0 as Reduce leaves it into the limbs of SM2Field52 as the same integer.
	private sealed class Conversions : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			int laneCount = TField.LaneCount;
			TField.One(out TField one);

			for (int lane = 0; lane < laneCount; ++lane)
			{
				if (!LaneLimbs(in one, lane).SequenceEqual(Split(R % P)))
				{
					failures.Add($"One, lane {lane}: {Show(LaneLimbs(in one, lane))}");
				}
			}

			Random random = new(5);
			BigInteger[] coordinates = [0, 1, P - 1, (BigInteger.One << 255) + 12345, .. Enumerable.Range(0, 2 * laneCount + 4).Select(_ => RandomBelow(random, P))];

			for (int start = 0; start + 2 * laneCount <= coordinates.Length; start += 2)
			{
				ulong[] entries = new ulong[8 * laneCount];

				for (int lane = 0; lane < laneCount; ++lane)
				{
					WriteLimbs(coordinates[start + 2 * lane], entries.AsSpan(8 * lane, 4));
					WriteLimbs(coordinates[start + 2 * lane + 1], entries.AsSpan(8 * lane + 4, 4));
				}

				TField.LoadEntries(in entries[0], out TField x, out TField y);

				for (int lane = 0; lane < laneCount; ++lane)
				{
					if (!LaneLimbs(in x, lane).SequenceEqual(Split(2 * coordinates[start + 2 * lane])) || !LaneLimbs(in y, lane).SequenceEqual(Split(2 * coordinates[start + 2 * lane + 1])))
					{
						failures.Add($"LoadEntries from {start}, lane {lane}: {Show(LaneLimbs(in x, lane))}, {Show(LaneLimbs(in y, lane))}");
					}
				}

				TField.Halve(in x, out x);
				TField.Reduce(in x, out x);
				CheckJoin(failures, in x, coordinates[start]);
			}

			// Values as Reduce leaves them, up to limbs of 2^29 − 1 and limb 8 of 2^24 + 2^5 − 1.
			List<ulong[]> reduced = [Split(2 * P - 1), Split(P), Split(1), [.. Repeat(Nominal - 1).Take(8), (1UL << 24) + 31], [.. Repeat(Nominal - 2).Take(8), (1UL << 24) + 31]];

			for (int i = 0; i < 2 * RandomCount; ++i)
			{
				reduced.Add(Split(RandomBelow(random, 2 * P)));
			}

			foreach (ulong[] limbs in reduced)
			{
				TField value = FromLanes<TField>([.. Enumerable.Repeat(limbs, laneCount)]);
				CheckJoin(failures, in value, ValueOf(limbs));
			}

			return failures;
		}

		private static void CheckJoin<TField>(List<string> failures, in TField value, BigInteger expected) where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			SM2Field29.ToField52(in MemoryMarshal.Cast<TField, ulong>(new ReadOnlySpan<TField>(in value))[0], TField.LaneCount, out SM2Field52 packed);
			ulong[] packedLimbs = [packed.L0, packed.L1, packed.L2, packed.L3, packed.L4];
			BigInteger packedValue = packedLimbs.Select(static (limb, i) => (BigInteger)limb << 52 * i).Aggregate(BigInteger.Zero, static (sum, term) => sum + term);

			if (packedValue != expected || packedLimbs.Take(4).Any(static limb => limb >= 1UL << 52) || packed.L4 >= 1UL << 49)
			{
				failures.Add($"ToField52 of {Show(LaneLimbs(in value, 0))}: {string.Join(":", packedLimbs.Select(static limb => limb.ToString("X")))}");
			}
		}

		internal static void WriteLimbs(BigInteger value, Span<ulong> destination)
		{
			for (int i = 0; i < destination.Length; ++i)
			{
				destination[i] = (ulong)(value >> 64 * i & ulong.MaxValue);
			}
		}
	}

	// SM2Vector.Pack takes values as Reduce leaves them, below 2p in limbs 0 to 7 below 2^29 and limb 8 below 2^24 + 2^5, to the value of each lane mod p in four 64-bit limbs, limb k of lane l at k·LaneCount + l: the values from p on lose p, around p, 2p and the largest limbs, and random ones below 2p.
	private sealed class Packs : ISM2Field29LanesVisitor<List<string>>
	{
		public List<string> Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>
		{
			List<string> failures = [];
			Random random = new(6);
			List<ulong[]> values = [Split(0), Split(1), Split(P - 1), Split(P), Split(P + 1), Split(2 * P - 1), [.. Repeat(Nominal - 1).Take(8), (1UL << 24) + 31], [.. Repeat(0).Take(8), (1UL << 24) + 31]];

			for (int i = 0; i < 2 * RandomCount; ++i)
			{
				values.Add(Split(RandomBelow(random, 2 * P)));
			}

			int laneCount = TField.LaneCount;
			ulong[] words = new ulong[4 * laneCount];

			foreach (ulong[][] lanes in Lanes(laneCount, values, 1))
			{
				TField value = FromLanes<TField>(lanes);
				SM2Vector<TField>.Pack(in value, words);

				for (int lane = 0; lane < laneCount; ++lane)
				{
					ulong[] expected = new ulong[4];
					ulong[] actual = new ulong[4];
					Conversions.WriteLimbs(ValueOf(lanes[lane]) % P, expected);

					for (int k = 0; k < 4; ++k)
					{
						actual[k] = words[k * laneCount + lane];
					}

					if (!actual.AsSpan().SequenceEqual(expected))
					{
						failures.Add($"Pack of {Show(lanes[lane])}, lane {lane}: {Show(actual)}");
					}
				}
			}

			return failures;
		}
	}
}
