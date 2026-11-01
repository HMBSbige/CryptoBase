using BenchmarkDotNet.Attributes;
using CryptoBase.EllipticCurves.Curve25519;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The products of each four-lane field, on operands that start on a 64-byte line as the kernels keep them: a chain of products gives the latency of one, and two chains side by side its throughput. A chain of doublings, each DoubleOperands and the product of its operands, gives the latency of a doubling. A vector field adds its own FieldKind.
public unsafe class Curve25519VectorFieldBenchmark
{
	private const int Operations = 64;

	private IField _field = new Field<Field25519x4Avx2>(Field25519x4Avx2.Create);

	private delegate void Creator<TField>(in Field25519 a, in Field25519 b, in Field25519 c, in Field25519 d, out TField result);

	public enum FieldKind
	{
		Avx2,
		Avx512,
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
			FieldKind.Avx2 => new Field<Field25519x4Avx2>(Field25519x4Avx2.Create),
			FieldKind.Avx512 => new Field<Field25519x8Avx512>(CreateGroups),
			FieldKind.Sse41 => new Field<Field25519x4Sse41>(Field25519x4Sse41.Create),
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

	[Benchmark(OperationsPerInvoke = 2 * Operations)]
	public void MultiplyTwoChains()
	{
		_field.MultiplyTwoChains(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Double()
	{
		_field.Double(Operations);
	}

	// Both groups, the second with the lanes reversed.
	private static void CreateGroups(in Field25519 a, in Field25519 b, in Field25519 c, in Field25519 d, out Field25519x8Avx512 result)
	{
		Field25519x8Avx512.Create(in a, in b, in c, in d, in d, in c, in b, in a, out result);
	}

	private interface IField : IDisposable
	{
		bool IsSupported { get; }

		void Multiply(int count);

		void MultiplyTwoChains(int count);

		void Double(int count);
	}

	private sealed class Field<TField> : IField where TField : unmanaged, IEdwardsField25519x4<TField>
	{
		private TField* _values = (TField*)NativeMemory.AlignedAlloc((nuint)(3 * sizeof(TField)), 64);

		public Field(Creator<TField> create)
		{
			if (!TField.IsSupported)
			{
				return;
			}

			Field25519[] elements = new Field25519[4];

			for (int i = 0; i < elements.Length; ++i)
			{
				Field25519.FromBytes(RandomNumberGenerator.GetBytes(Field25519.ByteLength), out elements[i]);
			}

			for (int i = 0; i < 3; ++i)
			{
				create(in elements[i & 3], in elements[i + 1 & 3], in elements[i + 2 & 3], in elements[i + 3 & 3], out _values[i]);
			}
		}

		public bool IsSupported => TField.IsSupported;

		public void Multiply(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TField.Multiply(in _values[0], in _values[2], out _values[0]);
			}
		}

		public void MultiplyTwoChains(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TField.Multiply(in _values[0], in _values[2], out _values[0]);
				TField.Multiply(in _values[1], in _values[2], out _values[1]);
			}
		}

		public void Double(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TField.DoubleOperands(in _values[0], out _values[1], out _values[2]);
				TField.Multiply(in _values[1], in _values[2], out _values[0]);
			}
		}

		public void Dispose()
		{
			NativeMemory.AlignedFree(_values);
			_values = null;
		}
	}
}
