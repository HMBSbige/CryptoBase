using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using System.Runtime.CompilerServices;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves.SM9;

// The point formulas of SM9PointLanes for every vector type the CPU supports, against those of SM9Curve. Both compute the same polynomials of the coordinates, so the coordinates agree as values, not only the points; that holds for inputs that are no points too, which takes the lazy reductions to their bounds.
public class SM9PointLanesTest
{
	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task OnePointFormulasMatchTheScalarOnes(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		Random random = new(8);
		await Assert.That(vector.Accept(new OnePoint(G1Points(random), G2Points(random)))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task LaneFormulasMatchTheScalarOnes(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		Random random = new(9);
		await Assert.That(vector.Accept(new EveryLane(G1Points(random), G2Points(random)))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task ConditionalNegationTakesTheMaskedLanesToThreePMinusTheValue(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		Random random = new(10);
		await Assert.That(vector.Accept(new Negation(ReducedElements(random, 16)))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task MixedAdditionTakesEntriesNegatedInTheLanes(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		Random random = new(11);
		await Assert.That(vector.Accept(new NegatedEntries(G1Points(random), G2Points(random)))).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task AffineFormsMatchTheScalarOnes(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		Random random = new(12);
		await Assert.That(vector.Accept(new Affine(G1Points(random), G2Points(random)))).IsEmpty();
	}

	// Points of G1 with random Z, the point at infinity, a point twice in two forms, a point and its negation, and triples of extreme raw coordinates, which lie on no curve.
	private static List<SM9Point<SM9Fp>> G1Points(Random random)
	{
		G1Value p = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		List<SM9Point<SM9Fp>> points = [Projective(p, 7), Projective(p, 1), Projective(Negate(p), 3), Projective(null, 5), Projective(Multiply(P1, RandomBelow(random, N - 1) + 1), RandomBelow(random, P - 1) + 1)];
		SM9Fp[] extremes = [default, Raw(ReducedBound - 1), Raw((ReducedBound - 1 >> 208 << 208) - 1), Raw(P - 1)];

		for (int i = 0; i < 8; ++i)
		{
			points.Add(new SM9Point<SM9Fp> { X = extremes[random.Next(extremes.Length)], Y = extremes[random.Next(extremes.Length)], Z = extremes[random.Next(extremes.Length)] });
		}

		points.Add(new SM9Point<SM9Fp> { X = extremes[1], Y = extremes[1], Z = extremes[1] });
		return points;
	}

	private static List<SM9Point<SM9Fp2>> G2Points(Random random)
	{
		G2Value p = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
		List<SM9Point<SM9Fp2>> points = [Projective(p, new Fp2Value(7, 3)), Projective(p, Fp2Value.One), Projective(Negate(p), new Fp2Value(3, 0)), Projective(null, new Fp2Value(5, 2)), Projective(Multiply(P2, RandomBelow(random, N - 1) + 1), new Fp2Value(RandomBelow(random, P), RandomBelow(random, P - 1) + 1))];
		SM9Fp[] extremes = [default, Raw(ReducedBound - 1), Raw((ReducedBound - 1 >> 208 << 208) - 1), Raw(P - 1)];

		SM9Fp2 Pick()
		{
			return new SM9Fp2 { A0 = extremes[random.Next(extremes.Length)], A1 = extremes[random.Next(extremes.Length)] };
		}

		for (int i = 0; i < 8; ++i)
		{
			points.Add(new SM9Point<SM9Fp2> { X = Pick(), Y = Pick(), Z = Pick() });
		}

		SM9Fp2 largest = new() { A0 = extremes[1], A1 = extremes[1] };
		points.Add(new SM9Point<SM9Fp2> { X = largest, Y = largest, Z = largest });
		return points;
	}

	private static string Text(in SM9Point<SM9Fp> point)
	{
		return $"({ValueOf(point.X):X}, {ValueOf(point.Y):X}, {ValueOf(point.Z):X})";
	}

	private static string Text(in SM9Point<SM9Fp2> point)
	{
		return $"({ValueOf(point.X)}, {ValueOf(point.Y)}, {ValueOf(point.Z)})";
	}

	// Each pair of points through AddSingle, and each point through DoubleSingle, then the chains 2P, 2P + Q, 2(2P + Q) and 4(2P + Q) + Q on the outputs as they are, as the products take them.
	private sealed class OnePoint(List<SM9Point<SM9Fp>> g1, List<SM9Point<SM9Fp2>> g2) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			Check<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>(g1, Text, failures);
			Check<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(g2, Text, failures);
			return failures;
		}

		private delegate string Show<TField>(in SM9Point<TField> point) where TField : unmanaged, ISM9Field<TField>;

		private static void Check<TVector, TLanes, TField>(List<SM9Point<TField>> points, Show<TField> show, List<string> failures) where TVector : unmanaged, ISM9Vector<TVector> where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			int e = TLanes.ElementLength;
			ulong[] buffer = GC.AllocateArray<ulong>(4 * e + SM9PointLanes<TVector, TLanes, TField>.SingleWorkLength, true);
			ref ulong single = ref buffer[0];
			ref ulong entry = ref buffer[e];
			ref ulong work = ref buffer[4 * e];

			// The point of single, joined from a copy, as JoinSingle reduces in place.
			string Out(ref ulong rows)
			{
				ref ulong copy = ref buffer[2 * e];
				Unsafe.CopyBlockUnaligned(ref Unsafe.As<ulong, byte>(ref copy), ref Unsafe.As<ulong, byte>(ref rows), (uint)(e * sizeof(ulong)));
				SM9PointLanes<TVector, TLanes, TField>.JoinSingle(ref copy, out SM9Point<TField> result);
				return show(in result);
			}

			foreach (SM9Point<TField> p in points)
			{
				SM9Curve<TField>.Double(in p, out SM9Point<TField> twice);
				SM9PointLanes<TVector, TLanes, TField>.SplitSingle(in p, ref single);
				SM9PointLanes<TVector, TLanes, TField>.DoubleSingle(ref single, ref single, ref work);

				if (Out(ref single) != show(in twice))
				{
					failures.Add($"{typeof(TVector).Name} 2·{show(in p)}");
				}

				foreach (SM9Point<TField> q in points)
				{
					SM9Curve<TField>.Add(in p, in q, out SM9Point<TField> sum);
					SM9PointLanes<TVector, TLanes, TField>.SplitSingle(in p, ref single);
					SM9PointLanes<TVector, TLanes, TField>.SplitEntry(in q, ref entry);
					SM9PointLanes<TVector, TLanes, TField>.AddSingle(ref single, ref entry, ref single, ref work);

					if (Out(ref single) != show(in sum))
					{
						failures.Add($"{typeof(TVector).Name} {show(in p)} + {show(in q)}");
					}

					// 2P + Q from the unreduced double, then the chain.
					SM9PointLanes<TVector, TLanes, TField>.SplitSingle(in p, ref single);
					SM9PointLanes<TVector, TLanes, TField>.DoubleSingle(ref single, ref single, ref work);
					SM9PointLanes<TVector, TLanes, TField>.AddSingle(ref single, ref entry, ref single, ref work);
					SM9Curve<TField>.Add(in twice, in q, out SM9Point<TField> chain);

					for (int k = 0; k < 3; ++k)
					{
						SM9PointLanes<TVector, TLanes, TField>.DoubleSingle(ref single, ref single, ref work);
						SM9Curve<TField>.Double(in chain, out chain);
					}

					SM9PointLanes<TVector, TLanes, TField>.AddSingle(ref single, ref entry, ref single, ref work);
					SM9Curve<TField>.Add(in chain, in q, out chain);

					if (Out(ref single) != show(in chain))
					{
						failures.Add($"{typeof(TVector).Name} chain of {show(in p)} and {show(in q)}");
					}
				}
			}
		}
	}

	// MixedAdd and Add on a pair of points in each lane of vector 0, from the formulas' bounds: the left point weakly reduced, as the products keep it, and the right one as reduced as the tables have it.
	private sealed class EveryLane(List<SM9Point<SM9Fp>> g1, List<SM9Point<SM9Fp2>> g2) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			Check<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>(g1, Text, failures);
			Check<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(g2, Text, failures);
			return failures;
		}

		private delegate string Show<TField>(in SM9Point<TField> point) where TField : unmanaged, ISM9Field<TField>;

		private static void Check<TVector, TLanes, TField>(List<SM9Point<TField>> points, Show<TField> show, List<string> failures) where TVector : unmanaged, ISM9Vector<TVector> where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			int e = TLanes.ElementLength;
			int lanes = TVector.Count;
			ulong[] buffer = GC.AllocateArray<ulong>(9 * e + SM9PointLanes<TVector, TLanes, TField>.WorkspaceLength, true);
			ref ulong left = ref buffer[0];
			ref ulong right = ref buffer[3 * e];
			ref ulong result = ref buffer[6 * e];
			ref ulong formula = ref buffer[9 * e];
			int pairs = points.Count * points.Count;

			for (int start = 0; start < pairs; start += lanes)
			{
				for (int lane = 0; lane < lanes; ++lane)
				{
					int pair = (start + lane) % pairs;
					SM9PointLanes<TVector, TLanes, TField>.SplitPoint(points[pair / points.Count], ref left, lane);
					SM9PointLanes<TVector, TLanes, TField>.SplitPoint(points[pair % points.Count], ref right, lane);
				}

				SM9PointLanes<TVector, TLanes, TField>.WeakReducePoint(ref left);
				SM9PointLanes<TVector, TLanes, TField>.MixedAdd(ref left, ref right, ref result, ref formula);
				Compare(ref left, ref result, true, ref right);
				SM9PointLanes<TVector, TLanes, TField>.WeakReducePoint(ref right);
				SM9PointLanes<TVector, TLanes, TField>.Add(ref left, ref right, ref result, ref formula);
				Compare(ref left, ref result, false, ref right);
			}

			void Compare(ref ulong leftRows, ref ulong resultRows, bool affine, ref ulong rightRows)
			{
				for (int lane = 0; lane < lanes; ++lane)
				{
					SM9PointLanes<TVector, TLanes, TField>.JoinPoint(ref leftRows, lane, out SM9Point<TField> p);
					SM9PointLanes<TVector, TLanes, TField>.JoinPoint(ref rightRows, lane, out SM9Point<TField> q);
					SM9PointLanes<TVector, TLanes, TField>.JoinPoint(ref resultRows, lane, out SM9Point<TField> sum);
					SM9Point<TField> expected;

					if (affine)
					{
						SM9AffinePoint<TField> r = new() { X = q.X, Y = q.Y };
						SM9Curve<TField>.Add(in p, in r, out expected);
					}
					else
					{
						SM9Curve<TField>.Add(in p, in q, out expected);
					}

					if (show(in sum) != show(in expected))
					{
						failures.Add($"{typeof(TVector).Name} {(affine ? "MixedAdd" : "Add")} {show(in p)} + {show(in q)}");
					}
				}
			}
		}
	}

	// ConditionalNegate on reduced components in the lanes of vector 0, in turn under the masks of the odd lanes, of every lane and of none: each masked lane holds 3p − x exactly in limbs below 2^27, and every other lane, those past vector 0 included, keeps its rows.
	private sealed class Negation(List<SM9Fp> values) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			Check<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>(1, failures);
			Check<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(2, failures);
			return failures;
		}

		// Each component of an element of Fp2Lanes takes ten rows of its own, as one of FpLanes.
		private void Check<TVector, TLanes, TField>(int components, List<string> failures) where TVector : unmanaged, ISM9Vector<TVector> where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			const int rowLength = 8;
			const int componentLength = 10 * rowLength;
			int lanes = TVector.Count;
			ulong[] rows = GC.AllocateArray<ulong>(components * componentLength, true);
			ulong[] before = new ulong[rows.Length];
			ulong[] mask = GC.AllocateArray<ulong>(rowLength, true);
			BigInteger threeP = 3 * P;

			for (int start = 0; start < values.Count * components; start += lanes)
			{
				int pattern = start / lanes % 3;

				for (int lane = 0; lane < rowLength; ++lane)
				{
					for (int c = 0; c < components; ++c)
					{
						SM9Lanes<TVector>.FpLanes.Split(values[(start + lane + c) % values.Count], ref rows[c * componentLength], lane);
					}

					mask[lane] = pattern switch
					{
						0 => (lane & 1) is 1 ? ulong.MaxValue : 0,
						1 => ulong.MaxValue,
						_ => 0
					};
				}

				rows.CopyTo(before, 0);
				TLanes.ConditionalNegate(ref mask[0], ref rows[0]);

				for (int lane = 0; lane < rowLength; ++lane)
				{
					bool negated = lane < lanes && mask[lane] is not 0;

					for (int c = 0; c < components; ++c)
					{
						BigInteger value = 0;
						BigInteger original = 0;
						bool small = true;

						for (int l = 0; l < 10; ++l)
						{
							ulong limb = rows[c * componentLength + l * rowLength + lane];
							value += (BigInteger)limb << 26 * l;
							original += (BigInteger)before[c * componentLength + l * rowLength + lane] << 26 * l;
							small &= limb < 1UL << 27;
						}

						bool right = negated ? small && value == threeP - original : value == original && Enumerable.Range(0, 10).All(l => rows[c * componentLength + l * rowLength + lane] == before[c * componentLength + l * rowLength + lane]);

						if (!right)
						{
							failures.Add($"{typeof(TVector).Name} {typeof(TField).Name} lane {lane} component {c} of {original:X}, negated {negated}");
						}
					}
				}
			}
		}
	}

	// MixedAdd on a pair of points in each lane of vector 0, with the y of the right point negated in the lanes by ConditionalNegate, under the mask of the odd pairs: the sums match those of SM9Curve with the negated entry.
	private sealed class NegatedEntries(List<SM9Point<SM9Fp>> g1, List<SM9Point<SM9Fp2>> g2) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			Check<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>(g1, Text, failures);
			Check<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(g2, Text, failures);
			return failures;
		}

		private delegate string Show<TField>(in SM9Point<TField> point) where TField : unmanaged, ISM9Field<TField>;

		private static void Check<TVector, TLanes, TField>(List<SM9Point<TField>> points, Show<TField> show, List<string> failures) where TVector : unmanaged, ISM9Vector<TVector> where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			int e = TLanes.ElementLength;
			int lanes = TVector.Count;
			ulong[] buffer = GC.AllocateArray<ulong>(9 * e + 8 + SM9PointLanes<TVector, TLanes, TField>.WorkspaceLength, true);
			ref ulong left = ref buffer[0];
			ref ulong right = ref buffer[3 * e];
			ref ulong result = ref buffer[6 * e];
			ref ulong mask = ref buffer[9 * e];
			ref ulong formula = ref buffer[9 * e + 8];
			int pairs = points.Count * points.Count;

			for (int start = 0; start < pairs; start += lanes)
			{
				for (int lane = 0; lane < lanes; ++lane)
				{
					int pair = (start + lane) % pairs;
					SM9PointLanes<TVector, TLanes, TField>.SplitPoint(points[pair / points.Count], ref left, lane);
					SM9PointLanes<TVector, TLanes, TField>.SplitPoint(points[pair % points.Count], ref right, lane);
					Unsafe.Add(ref mask, lane) = (pair & 1) is 1 ? ulong.MaxValue : 0;
				}

				SM9PointLanes<TVector, TLanes, TField>.WeakReducePoint(ref left);
				TLanes.ConditionalNegate(ref mask, ref Unsafe.Add(ref right, e));
				SM9PointLanes<TVector, TLanes, TField>.MixedAdd(ref left, ref right, ref result, ref formula);

				for (int lane = 0; lane < lanes; ++lane)
				{
					int pair = (start + lane) % pairs;
					SM9PointLanes<TVector, TLanes, TField>.JoinPoint(ref left, lane, out SM9Point<TField> p);
					SM9PointLanes<TVector, TLanes, TField>.JoinPoint(ref result, lane, out SM9Point<TField> sum);
					SM9Point<TField> q = points[pair % points.Count];
					SM9AffinePoint<TField> r = new() { X = q.X, Y = q.Y };

					if ((pair & 1) is 1)
					{
						TField.Negate(in q.Y, out r.Y);
					}

					SM9Curve<TField>.Add(in p, in r, out SM9Point<TField> expected);

					if (show(in sum) != show(in expected))
					{
						failures.Add($"{typeof(TVector).Name} MixedAdd {show(in p)} + {show(in q)}, negated {(pair & 1) is 1}");
					}
				}
			}
		}
	}

	// ToAffine on the lanes against SM9Curve.ToAffine, in variable and in constant time, for every count up to 17, which fills rows of eight or leaves some lanes of the last, from the points other than the point at infinity, repeated.
	private sealed class Affine(List<SM9Point<SM9Fp>> g1, List<SM9Point<SM9Fp2>> g2) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			Check<TVector, SM9Lanes<TVector>.FpLanes, SM9Fp>(g1, failures);
			Check<TVector, SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(g2, failures);
			return failures;
		}

		private static void Check<TVector, TLanes, TField>(List<SM9Point<TField>> points, List<string> failures) where TVector : unmanaged, ISM9Vector<TVector> where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			SM9Point<TField>[] finite = [.. points.Where(static p => TField.IsZero(in p.Z) is 0)];

			for (int count = 1; count <= 17; ++count)
			{
				SM9Point<TField>[] input = [.. Enumerable.Range(0, count).Select(i => finite[i % finite.Length])];

				foreach (bool variableTime in (bool[])[false, true])
				{
					SM9AffinePoint<TField>[] expected = new SM9AffinePoint<TField>[count];
					SM9AffinePoint<TField>[] result = new SM9AffinePoint<TField>[count];
					SM9Curve<TField>.ToAffine(input, expected, variableTime);
					SM9PointLanes<TVector, TLanes, TField>.ToAffine(input, result, variableTime);

					for (int i = 0; i < count; ++i)
					{
						if (TField.AreEqual(in result[i].X, in expected[i].X) is 0 || TField.AreEqual(in result[i].Y, in expected[i].Y) is 0)
						{
							failures.Add($"{typeof(TVector).Name} {typeof(TField).Name} {count} points, variable time {variableTime}, point {i}");
						}
					}
				}
			}
		}
	}
}
