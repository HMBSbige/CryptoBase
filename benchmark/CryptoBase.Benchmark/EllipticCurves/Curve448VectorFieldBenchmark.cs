using BenchmarkDotNet.Attributes;
using CryptoBase.EllipticCurves.Curve448;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The steps of each four-lane field of p448, on values that start on a 64-byte line as the ladder keeps them: a chain of ladder steps gives the latency of one, and two chains side by side its throughput. The point formulas include the lookup or load of their entry, which SelectBase gives alone. A vector field adds its own FieldKind.
public unsafe class Curve448VectorFieldBenchmark
{
	private const int Operations = 64;

	private IField _field = new Field<Field448x4Avx2>();

	public enum FieldKind
	{
		Avx2,
		Avx512,
		AdvSimd,
		Sse41
	}

	[ParamsAllValues]
	public FieldKind Backend { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_field.Dispose();
		_field = Backend switch
		{
			FieldKind.Avx2 => new Field<Field448x4Avx2>(),
			FieldKind.Avx512 => new Field<Field448x4Avx512>(),
			FieldKind.AdvSimd => new Field<Field448x4AdvSimd>(),
			FieldKind.Sse41 => new Field<Field448x4Sse41>(),
			_ => throw new ArgumentOutOfRangeException(nameof(Backend))
		};

		if (!_field.IsSupported)
		{
			throw new NotSupportedException($"{Backend} is not supported here.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_field.Dispose();
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void LadderStep()
	{
		_field.LadderStep(Operations);
	}

	[Benchmark(OperationsPerInvoke = 2 * Operations)]
	public void LadderStepTwoChains()
	{
		_field.LadderStepTwoChains(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void SelectBase()
	{
		_field.SelectBase(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void TwistedAdd()
	{
		_field.TwistedAdd(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void TwistedDouble()
	{
		_field.TwistedDouble(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Add()
	{
		_field.Add(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Double()
	{
		_field.Double(Operations);
	}

	private interface IField : IDisposable
	{
		bool IsSupported { get; }

		void LadderStep(int count);

		void LadderStepTwoChains(int count);

		void SelectBase(int count);

		void TwistedAdd(int count);

		void TwistedDouble(int count);

		void Add(int count);

		void Double(int count);
	}

	// Two values, then the multiplier and the scratch of two steps. The point formulas take the first value as the point, and each addition a different table entry.
	private sealed class Field<TField> : IField where TField : unmanaged, IEdwardsField448x4<TField>
	{
		private readonly int _length = 2 + TField.MultiplierLength + 2 * TField.ScratchLength;
		private TField* _values;

		public Field()
		{
			_values = (TField*)NativeMemory.AlignedAlloc((nuint)(_length * sizeof(TField)), 64);
			new Span<TField>(_values, _length).Clear();

			if (!TField.IsSupported)
			{
				return;
			}

			Field448[] elements = new Field448[4];

			for (int i = 0; i < elements.Length; ++i)
			{
				Span<ulong> limbs = MemoryMarshal.Cast<Field448, ulong>(new Span<Field448>(ref elements[i]));
				RandomNumberGenerator.Fill(MemoryMarshal.AsBytes(limbs));

				for (int j = 0; j < limbs.Length; ++j)
				{
					limbs[j] &= (1UL << 56) - 1;
				}
			}

			for (int i = 0; i < 2; ++i)
			{
				TField.Create(in elements[i & 3], in elements[i + 1 & 3], in elements[i + 2 & 3], in elements[i + 3 & 3], out _values[i]);
			}

			TField.CreateMultiplier(in elements[3], new Span<TField>(_values + 2, TField.MultiplierLength));
		}

		public bool IsSupported => TField.IsSupported;

		public void LadderStep(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TField.LadderStep(ref _values[0], (ulong)(i & 1) - 1, in _values[2], ref _values[2 + TField.MultiplierLength]);
			}
		}

		public void LadderStepTwoChains(int count)
		{
			int scratch = 2 + TField.MultiplierLength;

			for (int i = 0; i < count; ++i)
			{
				TField.LadderStep(ref _values[0], (ulong)(i & 1) - 1, in _values[2], ref _values[scratch]);
				TField.LadderStep(ref _values[1], (ulong)(i & 1) - 1, in _values[2], ref _values[scratch + TField.ScratchLength]);
			}
		}

		public void SelectBase(int count)
		{
			ref TField scratch = ref _values[2 + TField.MultiplierLength];

			for (int i = 0; i < count; ++i)
			{
				TField.SelectBase(i % TwistedBaseTable.CombCount, (uint)i & TwistedBaseTable.CombLength - 1, 0 - (ulong)(i & 1), ref scratch);
			}
		}

		public void TwistedAdd(int count)
		{
			ref TField scratch = ref _values[2 + TField.MultiplierLength];

			for (int i = 0; i < count; ++i)
			{
				TField.SelectBase(i % TwistedBaseTable.CombCount, (uint)i & TwistedBaseTable.CombLength - 1, 0 - (ulong)(i & 1), ref scratch);
				TField.TwistedAdd(ref _values[0], ref scratch);
			}
		}

		public void TwistedDouble(int count)
		{
			ref TField scratch = ref _values[2 + TField.MultiplierLength];

			for (int i = 0; i < count; ++i)
			{
				TField.TwistedDouble(ref _values[0], ref scratch);
			}
		}

		public void Add(int count)
		{
			ref TField scratch = ref _values[2 + TField.MultiplierLength];
			EdwardsAffinePoint[] entries = EdwardsVariableTimeBaseTable.Entries;

			for (int i = 0; i < count; ++i)
			{
				TField.LoadAffine(in entries[i & 7], (i & 1) is 0, ref scratch);
				TField.Add(ref _values[0], ref scratch);
			}
		}

		public void Double(int count)
		{
			ref TField scratch = ref _values[2 + TField.MultiplierLength];

			for (int i = 0; i < count; ++i)
			{
				TField.Double(ref _values[0], ref scratch);
			}
		}

		public void Dispose()
		{
			NativeMemory.AlignedFree(_values);
			_values = null;
		}
	}
}
