using BenchmarkDotNet.Attributes;
using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Signatures.Rsa.Arithmetic;

// The kernel that MontgomeryKernelDispatch picks for a modulus of each size: a chain of multiplications or squarings, each taking the previous result, and a constant-time exponentiation with an exponent as long as the modulus.
public class RsaMontgomeryBenchmark
{
	private const int Operations = 64;

	private IKernel _kernel = null!;
	private MontgomeryContext _context = null!;
	private ulong[] _element = [];
	private ulong[] _exponent = [];
	private ulong[] _result = [];

	[Params(1024, 1536, 2048, 3072, 4096, 8192, 16384)]
	public int Bits { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		int limbs = Bits / 64;
		ulong[] modulus = Random(limbs);
		modulus[0] |= 1;
		modulus[^1] |= 1UL << 63;
		_context = MontgomeryKernelDispatch.Create(modulus);
		Type kernelType = _context.GetType().GetGenericArguments()[0];
		_kernel = (IKernel)Activator.CreateInstance(typeof(Kernel<>).MakeGenericType(kernelType), modulus, _context.DigitCount)!;
		_element = new ulong[_context.DigitCount];
		_result = new ulong[_context.DigitCount];
		_context.ToMontgomery(Random(limbs), _element);
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
		_kernel.Multiply(Operations);
	}

	[Benchmark(OperationsPerInvoke = Operations)]
	public void Square()
	{
		_kernel.Square(Operations);
	}

	[Benchmark]
	public void Exponentiate()
	{
		_context.Exponentiate(_element, _exponent, _result);
	}

	private static ulong[] Random(int limbs)
	{
		ulong[] value = new ulong[limbs];
		RandomNumberGenerator.Fill(System.Runtime.InteropServices.MemoryMarshal.AsBytes(value.AsSpan()));
		return value;
	}

	private interface IKernel
	{
		void Multiply(int count);

		void Square(int count);
	}

	private sealed class Kernel<TKernel> : IKernel where TKernel : IMontgomeryKernel
	{
		private readonly ulong[] _modulus;
		private readonly ulong _negativeInverse;
		private readonly ulong[] _left;
		private readonly ulong[] _right;
		private readonly ulong[] _scratch;

		public Kernel(ulong[] modulus, int digits)
		{
			ulong mask = (1UL << TKernel.DigitBits) - 1;
			ulong[] modulusDigits = ToDigits(ToBigInteger(modulus), digits, mask);
			_modulus = new ulong[digits];
			TKernel.Prepare(modulusDigits, _modulus);
			ulong inverse = 3 * modulus[0] ^ 2;

			for (int i = 0; i < 4; ++i)
			{
				inverse *= 2 - modulus[0] * inverse;
			}

			_negativeInverse = 0 - inverse & mask;
			// Values below n, whose top bit is set.
			_left = ToDigits(RandomBelowModulus(modulus.Length), digits, mask);
			_right = ToDigits(RandomBelowModulus(modulus.Length), digits, mask);
			_scratch = new ulong[TKernel.GetScratchLength(digits)];
		}

		public void Multiply(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TKernel.Multiply(_left, _left, _right, _modulus, _negativeInverse, _scratch);
			}
		}

		public void Square(int count)
		{
			for (int i = 0; i < count; ++i)
			{
				TKernel.Square(_left, _left, _modulus, _negativeInverse, _scratch);
			}
		}

		private static BigInteger RandomBelowModulus(int limbs)
		{
			return ToBigInteger(Random(limbs)) >> 1;
		}

		private static ulong[] ToDigits(BigInteger value, int digits, ulong mask)
		{
			ulong[] result = new ulong[digits];

			for (int i = 0; i < digits; ++i)
			{
				result[i] = (ulong)(value >> TKernel.DigitBits * i & new BigInteger(mask));
			}

			return result;
		}

		private static BigInteger ToBigInteger(ulong[] limbs)
		{
			BigInteger value = BigInteger.Zero;

			for (int i = limbs.Length - 1; i >= 0; --i)
			{
				value = (value << 64) + limbs[i];
			}

			return value;
		}
	}
}
