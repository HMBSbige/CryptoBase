using BenchmarkDotNet.Attributes;
using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Signatures.Rsa.Arithmetic;

// The kernels that the dispatch chooses from on ARM64, each with the largest digits that fit the modulus, and MontgomeryKernel64, which it takes on other platforms: a chain of multiplications or squarings, each taking the previous result, and a constant-time exponentiation with an exponent as long as the modulus.
public class RsaMontgomeryArm64Benchmark
{
	private const int Operations = 64;

	private MontgomeryContext _context = null!;
	private ulong[] _left = [];
	private ulong[] _right = [];
	private ulong[] _exponent = [];

	[ParamsSource(nameof(Kernels))]
	public string Kernel { get; set; } = "";

	[Params(512, 1024, 1536, 2048, 3072, 4096, 8192, 16384)]
	public int Bits { get; set; }

	public static IEnumerable<string> Kernels()
	{
		if (MontgomeryKernel64<Radix57>.IsSupported)
		{
			yield return nameof(MontgomeryKernel64<>);
			yield return nameof(MontgomeryKernel64ColumnPairs<>);
		}

		if (MontgomeryKernelAdvSimd<Radix28>.IsSupported)
		{
			yield return nameof(MontgomeryKernelAdvSimd<>);
		}
	}

	[GlobalSetup]
	public void Setup()
	{
		int limbs = Bits / 64;
		ulong[] modulus = Random(limbs);
		modulus[0] |= 1;
		modulus[^1] |= 1UL << 63;
		_context = Kernel switch
		{
			nameof(MontgomeryKernel64<>) => Create<MontgomeryKernel64<Radix57>, MontgomeryKernel64<Radix56>, MontgomeryKernel64<Radix55>, MontgomeryKernel64<Radix54>>(modulus),
			nameof(MontgomeryKernel64ColumnPairs<>) => Create<MontgomeryKernel64ColumnPairs<Radix57>, MontgomeryKernel64ColumnPairs<Radix56>, MontgomeryKernel64ColumnPairs<Radix55>, MontgomeryKernel64ColumnPairs<Radix54>>(modulus),
			nameof(MontgomeryKernelAdvSimd<>) => Create<MontgomeryKernelAdvSimd<Radix28>, MontgomeryKernelAdvSimd<Radix27>, MontgomeryKernelAdvSimd<Radix26>, MontgomeryKernelAdvSimd<Radix26>>(modulus),
			_ => throw new InvalidOperationException(Kernel)
		};
		_left = new ulong[_context.DigitCount];
		_right = new ulong[_context.DigitCount];
		_context.ToMontgomery(Random(limbs), _left);
		_context.ToMontgomery(Random(limbs), _right);
		_exponent = Random(limbs);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_context.Dispose();
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Multiply()
	{
		for (int i = 0; i < Operations; ++i)
		{
			_context.Multiply(_left, _left, _right);
		}
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Square()
	{
		for (int i = 0; i < Operations; ++i)
		{
			_context.Square(_left, _left);
		}
	}

	[Benchmark]
	public void Exponentiate()
	{
		_context.Exponentiate(_right, _exponent, _left);
	}

	// The first of the kernels, from the largest digits down, that fits the modulus.
	private static MontgomeryContext Create<T1, T2, T3, T4>(ulong[] modulus) where T1 : IMontgomeryKernel where T2 : IMontgomeryKernel where T3 : IMontgomeryKernel where T4 : IMontgomeryKernel
	{
		int limbs = modulus.Length;

		if (MontgomeryContext<T1>.GetDigitCount(limbs) <= T1.MaxDigitCount)
		{
			return new MontgomeryContext<T1>(modulus);
		}

		if (MontgomeryContext<T2>.GetDigitCount(limbs) <= T2.MaxDigitCount)
		{
			return new MontgomeryContext<T2>(modulus);
		}

		return MontgomeryContext<T3>.GetDigitCount(limbs) <= T3.MaxDigitCount ? new MontgomeryContext<T3>(modulus) : new MontgomeryContext<T4>(modulus);
	}

	private static ulong[] Random(int limbs)
	{
		ulong[] value = new ulong[limbs];
		RandomNumberGenerator.Fill(System.Runtime.InteropServices.MemoryMarshal.AsBytes(value.AsSpan()));
		return value;
	}
}
