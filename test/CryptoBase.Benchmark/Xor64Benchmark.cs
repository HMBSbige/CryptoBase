using BenchmarkDotNet.Attributes;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[RankColumn]
public class Xor64Benchmark
{
	private Memory<byte> _a;
	private Memory<byte> _b;

	[GlobalSetup]
	public void Setup()
	{
		_a = RandomNumberGenerator.GetBytes(64);
		_b = RandomNumberGenerator.GetBytes(64);
	}

	[Benchmark(Baseline = true, Description = @"Normal")]
	public void A()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		for (int i = 0; i < 64; ++i)
		{
			a[i] ^= b[i];
		}
	}

	[Benchmark(Description = @"Without bounds checking")]
	public void B()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref byte refA = ref a.GetReference();
		ref byte refB = ref b.GetReference();

		for (int i = 0; i < 64; ++i)
		{
			Unsafe.Add(ref refA, i) ^= Unsafe.Add(ref refB, i);
		}
	}

	[Benchmark(Description = @"Vector512")]
	public void C()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref Vector512<byte> v0 = ref Unsafe.As<byte, Vector512<byte>>(ref a.GetReference());
		ref Vector512<byte> v1 = ref Unsafe.As<byte, Vector512<byte>>(ref b.GetReference());

		v0 ^= v1;
	}

	[Benchmark(Description = @"Vector256")]
	public void D()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref byte refA = ref a.GetReference();
		ref byte refB = ref b.GetReference();

		ref Vector256<byte> a0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref refA, 0 * Vector256<byte>.Count));
		ref Vector256<byte> a1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref refA, 1 * Vector256<byte>.Count));
		ref Vector256<byte> b0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref refB, 0 * Vector256<byte>.Count));
		ref Vector256<byte> b1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref refB, 1 * Vector256<byte>.Count));

		a0 ^= b0;
		a1 ^= b1;
	}

	[Benchmark(Description = @"Vector128")]
	public void D1()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref byte refA = ref a.GetReference();
		ref byte refB = ref b.GetReference();

		ref Vector128<byte> a0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refA, 0 * Vector128<byte>.Count));
		ref Vector128<byte> a1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refA, 1 * Vector128<byte>.Count));
		ref Vector128<byte> a2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refA, 2 * Vector128<byte>.Count));
		ref Vector128<byte> a3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refA, 3 * Vector128<byte>.Count));
		ref Vector128<byte> b0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refB, 0 * Vector128<byte>.Count));
		ref Vector128<byte> b1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refB, 1 * Vector128<byte>.Count));
		ref Vector128<byte> b2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refB, 2 * Vector128<byte>.Count));
		ref Vector128<byte> b3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref refB, 3 * Vector128<byte>.Count));

		a0 ^= b0;
		a1 ^= b1;
		a2 ^= b2;
		a3 ^= b3;
	}

	[Benchmark(Description = @"Unsafe")]
	public void E()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		unsafe
		{
			fixed (byte* pa = &a.GetReference())
			fixed (byte* pb = &b.GetReference())
			{
				for (int i = 0; i < 64; ++i)
				{
					*(pa + i) ^= *(pb + i);
				}
			}
		}
	}

	[Benchmark(Description = @"UInt128")]
	public void F()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref byte refA = ref a.GetReference();
		ref byte refB = ref b.GetReference();

		ref UInt128 a0 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refA, 0 * 16));
		ref UInt128 a1 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refA, 1 * 16));
		ref UInt128 a2 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refA, 2 * 16));
		ref UInt128 a3 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refA, 3 * 16));
		ref UInt128 b0 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refB, 0 * 16));
		ref UInt128 b1 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refB, 1 * 16));
		ref UInt128 b2 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refB, 2 * 16));
		ref UInt128 b3 = ref Unsafe.As<byte, UInt128>(ref Unsafe.Add(ref refB, 3 * 16));

		a0 ^= b0;
		a1 ^= b1;
		a2 ^= b2;
		a3 ^= b3;
	}

	[Benchmark(Description = @"ulong")]
	public void G()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref byte refA = ref a.GetReference();
		ref byte refB = ref b.GetReference();

		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 0 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 0 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 1 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 1 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 2 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 2 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 3 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 3 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 4 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 4 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 5 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 5 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 6 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 6 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 7 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 7 * sizeof(ulong)));
	}
}
