using BenchmarkDotNet.Attributes;
using CryptoBase.EllipticCurves.SM9;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The operations of the lane tower of the SM9 vector kernels and the point formulas of SM9PointLanes, each taking the previous result as an input, so the time per operation is its latency, on values that start on a 64-byte line as the kernels keep them: the mixed additions on a point in each lane, which a fixed-base product takes per round, and the doubling and addition on one point. A vector type adds its own LaneKind.
public unsafe class SM9LanesBenchmark
{
	private const int Operations = 64;

	private ILanes _lanes = new Lanes<SM9VectorAvx2>();

	public enum LaneKind
	{
		Avx512,
		Avx2,
		Sse41,
		AdvSimd
	}

	[ParamsAllValues]
	public LaneKind Backend { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_lanes.Dispose();
		_lanes = Backend switch
		{
			LaneKind.Avx512 => new Lanes<SM9VectorAvx512>(),
			LaneKind.Avx2 => new Lanes<SM9VectorAvx2>(),
			LaneKind.Sse41 => new Lanes<SM9VectorSse41>(),
			LaneKind.AdvSimd => new Lanes<SM9VectorAdvSimd>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Backend))
		};

		if (!_lanes.IsSupported)
		{
			throw new NotSupportedException($"{Backend} is not supported here.");
		}
	}

	// The doubling step in lanes takes vectors of a whole row.
	[GlobalSetup(Target = nameof(DoublingStep))]
	public void SetupDoubling()
	{
		Setup();

		if (!_lanes.FillsRow)
		{
			throw new NotSupportedException($"{Backend} does not fill a row.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_lanes.Dispose();
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Multiply()
	{
		_lanes.Multiply(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Square()
	{
		_lanes.Square(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void MultiplyByLine()
	{
		_lanes.MultiplyByLine(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void MultiplyByNormalizedLine()
	{
		_lanes.MultiplyByNormalizedLine(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void CyclotomicSquare()
	{
		_lanes.CyclotomicSquare(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Frobenius()
	{
		_lanes.Frobenius(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void DoublingStep()
	{
		_lanes.DoublingStep(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void MixedAddG1()
	{
		_lanes.MixedAddG1(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void DoubleSingleG1()
	{
		_lanes.DoubleSingleG1(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void AddSingleG1()
	{
		_lanes.AddSingleG1(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void MixedAddG2()
	{
		_lanes.MixedAddG2(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void DoubleSingleG2()
	{
		_lanes.DoubleSingleG2(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void AddSingleG2()
	{
		_lanes.AddSingleG2(Operations);
	}

	private interface ILanes : IDisposable
	{
		bool IsSupported { get; }

		bool FillsRow { get; }

		void Multiply(int count);

		void Square(int count);

		void MultiplyByLine(int count);

		void MultiplyByNormalizedLine(int count);

		void CyclotomicSquare(int count);

		void Frobenius(int count);

		void DoublingStep(int count);

		void MixedAddG1(int count);

		void DoubleSingleG1(int count);

		void AddSingleG1(int count);

		void MixedAddG2(int count);

		void DoubleSingleG2(int count);

		void AddSingleG2(int count);
	}

	// Four elements, then the scratch and a batch of lines; and the points of each group, the left one, the right one, the result and the workspace of the formulas, first on a point in each lane and then on one point.
	private sealed class Lanes<TVector> : ILanes where TVector : unmanaged, ISM9Vector<TVector>
	{
		private readonly SM9Fp12Lanes* _values;

		private readonly ulong* _g1;

		private readonly ulong* _g2;

		private readonly int _g1Single;

		private readonly int _g2Single;

		public Lanes()
		{
			nuint size = (nuint)(4 * sizeof(SM9Fp12Lanes) + sizeof(SM9LaneScratch) + SM9Lanes<TVector>.LineBatchLength * sizeof(ulong));
			_values = (SM9Fp12Lanes*)NativeMemory.AlignedAlloc(size, 64);
			NativeMemory.Clear(_values, size);

			if (!TVector.IsSupported)
			{
				return;
			}

			SM9Lanes<TVector>.FromFp12(Random12(), ref _values[0]);
			SM9Lanes<TVector>.FromFp12(Random12(), ref _values[1]);
			SM9Fp12 line = Random12();
			SM9Lanes<TVector>.FromLine(in line.C0.C0, in line.C0.C1, in line.C1.C1, ref _values[2]);
			SM9Point<SM9Fp2> point = new() { X = line.C0.C0, Y = line.C0.C1, Z = line.C1.C1 };
			SM9Lanes<TVector>.FromPoint(in point, ref _values[3]);
			SM9PrecomputedLine[] lines = new SM9PrecomputedLine[SM9Lanes<TVector>.BatchLines];

			for (int i = 0; i < lines.Length; ++i)
			{
				SM9Fp12 coefficients = Random12();
				lines[i] = new SM9PrecomputedLine { A = coefficients.C0.C0, B = coefficients.C1.C0 };
			}

			SM9Lanes<TVector>.SplitFactors(Random(), Random(), ref *Batch);
			SM9Lanes<TVector>.EvaluateLines(lines, ref *Batch, ref Scratch);
			_g1 = Points<SM9Lanes<TVector>.FpLanes, SM9Fp>(out _g1Single);
			_g2 = Points<SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(out _g2Single);
			SM9Curve<SM9Fp>.FromAffine(in SM9G1Group.Generator, out SM9Point<SM9Fp> g1);
			SM9Curve<SM9Fp2>.FromAffine(in SM9G2Group.Generator, out SM9Point<SM9Fp2> g2);
			Fill<SM9Lanes<TVector>.FpLanes, SM9Fp>(_g1, _g1Single, in g1);
			Fill<SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(_g2, _g2Single, in g2);
		}

		public bool IsSupported => TVector.IsSupported;

		public bool FillsRow => TVector.Count == SM9Lanes<TVector>.RowLength;

		private ref SM9LaneScratch Scratch => ref *(SM9LaneScratch*)(_values + 4);

		private ulong* Batch => (ulong*)((SM9LaneScratch*)(_values + 4) + 1);

		public void Multiply(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				SM9Lanes<TVector>.Multiply(ref _values[0], ref _values[1], ref _values[0], ref Scratch);
			}
		}

		public void Square(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				SM9Lanes<TVector>.Square(ref _values[0], ref _values[0], ref Scratch);
			}
		}

		public void MultiplyByLine(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				SM9Lanes<TVector>.MultiplyByLine(ref _values[0], ref _values[2], ref _values[0], ref Scratch);
			}
		}

		public void MultiplyByNormalizedLine(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				SM9Lanes<TVector>.MultiplyByNormalizedLine(ref _values[0], ref *Batch, 3, ref _values[0], ref Scratch);
			}
		}

		public void CyclotomicSquare(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				SM9Lanes<TVector>.CyclotomicSquare(ref _values[0], ref _values[0], ref Scratch);
			}
		}

		public void Frobenius(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				SM9Lanes<TVector>.Frobenius(ref _values[0], ref _values[0], ref Scratch);
			}
		}

		public void DoublingStep(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				SM9Lanes<TVector>.DoublingStep(ref _values[3], ref _values[1], ref _values[2], ref Scratch);
			}
		}

		public void MixedAddG1(int count)
		{
			MixedAdd<SM9Lanes<TVector>.FpLanes, SM9Fp>(_g1, count);
		}

		public void DoubleSingleG1(int count)
		{
			DoubleSingle<SM9Lanes<TVector>.FpLanes, SM9Fp>(_g1 + _g1Single, count);
		}

		public void AddSingleG1(int count)
		{
			AddSingle<SM9Lanes<TVector>.FpLanes, SM9Fp>(_g1 + _g1Single, count);
		}

		public void MixedAddG2(int count)
		{
			MixedAdd<SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(_g2, count);
		}

		public void DoubleSingleG2(int count)
		{
			DoubleSingle<SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(_g2 + _g2Single, count);
		}

		public void AddSingleG2(int count)
		{
			AddSingle<SM9Lanes<TVector>.Fp2Lanes, SM9Fp2>(_g2 + _g2Single, count);
		}

		public void Dispose()
		{
			NativeMemory.AlignedFree(_values);
			NativeMemory.AlignedFree(_g1);
			NativeMemory.AlignedFree(_g2);
		}

		// The points of a group in lanes: the left, the right and the result point in each lane with the workspace of the formulas, and from single on the point, the entry and the workspace of the formulas on one point.
		private static ulong* Points<TLanes, TField>(out int single) where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			int e = TLanes.ElementLength;
			single = 9 * e + SM9PointLanes<TVector, TLanes, TField>.WorkspaceLength;
			nuint size = (nuint)((single + 2 * e + SM9PointLanes<TVector, TLanes, TField>.SingleWorkLength) * sizeof(ulong));
			ulong* points = (ulong*)NativeMemory.AlignedAlloc(size, 64);
			NativeMemory.Clear(points, size);
			return points;
		}

		private static void Fill<TLanes, TField>(ulong* points, int single, in SM9Point<TField> point) where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			if (!TVector.IsSupported)
			{
				return;
			}

			int e = TLanes.ElementLength;

			for (int lane = 0; lane < TVector.Count; ++lane)
			{
				SM9PointLanes<TVector, TLanes, TField>.SplitPoint(in point, ref points[0], lane);
				SM9PointLanes<TVector, TLanes, TField>.SplitPoint(in point, ref points[3 * e], lane);
			}

			SM9PointLanes<TVector, TLanes, TField>.WeakReducePoint(ref points[0]);
			SM9PointLanes<TVector, TLanes, TField>.SplitSingle(in point, ref points[single]);
			SM9PointLanes<TVector, TLanes, TField>.SplitEntry(in point, ref points[single + e]);
		}

		// The sum of each round goes back to the left point, as the fixed-base products keep it.
		private static void MixedAdd<TLanes, TField>(ulong* points, int count) where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			int e = TLanes.ElementLength;

			for (int i = 0; i < count; ++i)
			{
				SM9PointLanes<TVector, TLanes, TField>.MixedAdd(ref points[0], ref points[3 * e], ref points[6 * e], ref points[9 * e]);
				Buffer.MemoryCopy(points + 6 * e, points, 3 * e * sizeof(ulong), 3 * e * sizeof(ulong));
			}
		}

		private static void DoubleSingle<TLanes, TField>(ulong* single, int count) where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			int e = TLanes.ElementLength;

			for (int i = 0; i < count; ++i)
			{
				SM9PointLanes<TVector, TLanes, TField>.DoubleSingle(ref single[0], ref single[0], ref single[2 * e]);
			}
		}

		private static void AddSingle<TLanes, TField>(ulong* single, int count) where TLanes : struct, ISM9FieldLanes<TField> where TField : unmanaged, ISM9Field<TField>
		{
			int e = TLanes.ElementLength;

			for (int i = 0; i < count; ++i)
			{
				SM9PointLanes<TVector, TLanes, TField>.AddSingle(ref single[0], ref single[e], ref single[0], ref single[2 * e]);
			}
		}

		private static SM9Fp Random()
		{
			SM9Fp.TryImport(RandomNumberGenerator.GetBytes(SM9Fp.ByteLength).AsSpan(), out SM9Fp value);
			value.L4 &= 0x7FFFFFFFFFFF;
			return value;
		}

		private static SM9Fp12 Random12()
		{
			SM9Fp12 value = default;
			value.C0.C0 = new SM9Fp2 { A0 = Random(), A1 = Random() };
			value.C0.C1 = new SM9Fp2 { A0 = Random(), A1 = Random() };
			value.C0.C2 = new SM9Fp2 { A0 = Random(), A1 = Random() };
			value.C1.C0 = new SM9Fp2 { A0 = Random(), A1 = Random() };
			value.C1.C1 = new SM9Fp2 { A0 = Random(), A1 = Random() };
			value.C1.C2 = new SM9Fp2 { A0 = Random(), A1 = Random() };
			return value;
		}
	}
}
