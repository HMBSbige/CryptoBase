using BenchmarkDotNet.Attributes;
using CryptoBase.EllipticCurves;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The products of each lane field of SM2, on values that start on a 64-byte line as SM2Vector keeps them: a chain of products gives the latency of one, and four chains side by side its throughput, for all the lanes at once. A lane field adds its own FieldKind.
public unsafe class SM2VectorFieldBenchmark
{
	private const int Operations = 64;

	private IField _field = new Field<SM2Field29x4Avx2>();

	public enum FieldKind
	{
		Avx512,
		Avx2,
		Vector128
	}

	[ParamsAllValues]
	public FieldKind Backend { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_field.Dispose();
		_field = Backend switch
		{
			FieldKind.Avx512 => new Field<SM2Field29x8Avx512>(),
			FieldKind.Avx2 => new Field<SM2Field29x4Avx2>(),
			FieldKind.Vector128 => new Field<SM2Field29x2>(),
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
	public void Multiply()
	{
		_field.Multiply(Operations);
	}

	[Benchmark(OperationsPerInvoke = 4 * Operations)]
	public void MultiplyFourChains()
	{
		_field.MultiplyFourChains(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Square()
	{
		_field.Square(Operations);
	}

	private interface IField : IDisposable
	{
		bool IsSupported { get; }

		void Multiply(int count);

		void MultiplyFourChains(int count);

		void Square(int count);
	}

	// Five values in native memory on a 64-byte line: four chains and the factor they share, with limbs below 2^29.
	private sealed class Field<TField> : IField where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		private const int Count = 5;

		private readonly TField* _values = (TField*)NativeMemory.AlignedAlloc((nuint)(Count * sizeof(TField)), 64);

		public Field()
		{
			Span<ulong> limbs = new(_values, Count * sizeof(TField) / sizeof(ulong));
			RandomNumberGenerator.Fill(MemoryMarshal.AsBytes(limbs));

			for (int i = 0; i < limbs.Length; ++i)
			{
				limbs[i] &= SM2Field29.Mask;
			}
		}

		public bool IsSupported => TField.IsSupported;

		public void Multiply(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TField.Multiply(in _values[0], in _values[4], out _values[0]);
			}
		}

		public void MultiplyFourChains(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TField.Multiply(in _values[0], in _values[4], out _values[0]);
				TField.Multiply(in _values[1], in _values[4], out _values[1]);
				TField.Multiply(in _values[2], in _values[4], out _values[2]);
				TField.Multiply(in _values[3], in _values[4], out _values[3]);
			}
		}

		public void Square(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TField.Square(in _values[0], out _values[0]);
			}
		}

		public void Dispose()
		{
			NativeMemory.AlignedFree(_values);
		}
	}
}
