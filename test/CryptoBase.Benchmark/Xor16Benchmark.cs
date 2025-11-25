using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[RankColumn]
public class Xor16Benchmark
{
	private Memory<byte> _a;
	private Memory<byte> _b;

	[GlobalSetup]
	public void Setup()
	{
		_a = RandomNumberGenerator.GetBytes(16);
		_b = RandomNumberGenerator.GetBytes(16);
	}

	[Benchmark(Baseline = true, Description = @"Normal")]
	public void A()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		for (int i = 0; i < 16; ++i)
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

		for (int i = 0; i < 16; ++i)
		{
			Unsafe.Add(ref refA, i) ^= Unsafe.Add(ref refB, i);
		}
	}

	[Benchmark(Description = @"Without bounds checking + unrolling")]
	public void B2()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref byte refA = ref a.GetReference();
		ref byte refB = ref b.GetReference();

		Unsafe.Add(ref refA, 0) ^= Unsafe.Add(ref refB, 0);
		Unsafe.Add(ref refA, 1) ^= Unsafe.Add(ref refB, 1);
		Unsafe.Add(ref refA, 2) ^= Unsafe.Add(ref refB, 2);
		Unsafe.Add(ref refA, 3) ^= Unsafe.Add(ref refB, 3);
		Unsafe.Add(ref refA, 4) ^= Unsafe.Add(ref refB, 4);
		Unsafe.Add(ref refA, 5) ^= Unsafe.Add(ref refB, 5);
		Unsafe.Add(ref refA, 6) ^= Unsafe.Add(ref refB, 6);
		Unsafe.Add(ref refA, 7) ^= Unsafe.Add(ref refB, 7);
		Unsafe.Add(ref refA, 8) ^= Unsafe.Add(ref refB, 8);
		Unsafe.Add(ref refA, 9) ^= Unsafe.Add(ref refB, 9);
		Unsafe.Add(ref refA, 10) ^= Unsafe.Add(ref refB, 10);
		Unsafe.Add(ref refA, 11) ^= Unsafe.Add(ref refB, 11);
		Unsafe.Add(ref refA, 12) ^= Unsafe.Add(ref refB, 12);
		Unsafe.Add(ref refA, 13) ^= Unsafe.Add(ref refB, 13);
		Unsafe.Add(ref refA, 14) ^= Unsafe.Add(ref refB, 14);
		Unsafe.Add(ref refA, 15) ^= Unsafe.Add(ref refB, 15);
	}

	[Benchmark(Description = @"Vector128")]
	public void C()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref Vector128<byte> v0 = ref Unsafe.As<byte, Vector128<byte>>(ref a.GetReference());
		ref Vector128<byte> v1 = ref Unsafe.As<byte, Vector128<byte>>(ref b.GetReference());

		v0 ^= v1;
	}

	[Benchmark(Description = @"SSE2")]
	public void D()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		unsafe
		{
			Vector128<byte> v0 = Sse2.LoadVector128((byte*)Unsafe.AsPointer(ref a.GetReference()));
			Vector128<byte> v1 = Sse2.LoadVector128((byte*)Unsafe.AsPointer(ref b.GetReference()));
			Vector128<byte> v = Sse2.Xor(v0, v1);
			Sse2.Store((byte*)Unsafe.AsPointer(ref a.GetReference()), v);
		}
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
				for (int i = 0; i < 16; ++i)
				{
					*(pa + i) ^= *(pb + i);
				}
			}
		}
	}

	[Benchmark(Description = @"Unsafe unrolling")]
	public void F()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		unsafe
		{
			fixed (byte* pa = &a.GetReference())
			fixed (byte* pb = &b.GetReference())
			{
				*(pa + 0) ^= *(pb + 0);
				*(pa + 1) ^= *(pb + 1);
				*(pa + 2) ^= *(pb + 2);
				*(pa + 3) ^= *(pb + 3);
				*(pa + 4) ^= *(pb + 4);
				*(pa + 5) ^= *(pb + 5);
				*(pa + 6) ^= *(pb + 6);
				*(pa + 7) ^= *(pb + 7);
				*(pa + 8) ^= *(pb + 8);
				*(pa + 9) ^= *(pb + 9);
				*(pa + 10) ^= *(pb + 10);
				*(pa + 11) ^= *(pb + 11);
				*(pa + 12) ^= *(pb + 12);
				*(pa + 13) ^= *(pb + 13);
				*(pa + 14) ^= *(pb + 14);
				*(pa + 15) ^= *(pb + 15);
			}
		}
	}

	[Benchmark(Description = @"UInt128")]
	public void G()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref UInt128 xa = ref Unsafe.As<byte, UInt128>(ref a.GetReference());
		ref UInt128 xb = ref Unsafe.As<byte, UInt128>(ref b.GetReference());

		xa ^= xb;
	}

	[Benchmark(Description = @"ulong")]
	public void G2()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref byte refA = ref a.GetReference();
		ref byte refB = ref b.GetReference();

		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 0 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 0 * sizeof(ulong)));
		Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refA, 1 * sizeof(ulong))) ^= Unsafe.As<byte, ulong>(ref Unsafe.Add(ref refB, 1 * sizeof(ulong)));
	}
}
