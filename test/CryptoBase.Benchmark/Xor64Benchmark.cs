using BenchmarkDotNet.Attributes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

		for (int i = 0; i < 64; ++i)
		{
			a.GetRef(i) ^= b.GetRef(i);
		}
	}

	[Benchmark(Description = @"Vector512")]
	public void C()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		ref Vector512<byte> v0 = ref Unsafe.As<byte, Vector512<byte>>(ref MemoryMarshal.GetReference(a));
		ref Vector512<byte> v1 = ref Unsafe.As<byte, Vector512<byte>>(ref MemoryMarshal.GetReference(b));

		v0 ^= v1;
	}

	[Benchmark(Description = @"Vector256")]
	public void D()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		Span<Vector256<byte>> xa = MemoryMarshal.Cast<byte, Vector256<byte>>(a);
		ReadOnlySpan<Vector256<byte>> xb = MemoryMarshal.Cast<byte, Vector256<byte>>(b);

		xa.GetRef(0) ^= xb.GetRef(0);
		xa.GetRef(1) ^= xb.GetRef(1);
	}

	[Benchmark(Description = @"Vector128")]
	public void D1()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		Span<Vector128<byte>> xa = MemoryMarshal.Cast<byte, Vector128<byte>>(a);
		ReadOnlySpan<Vector128<byte>> xb = MemoryMarshal.Cast<byte, Vector128<byte>>(b);

		xa.GetRef(0) ^= xb.GetRef(0);
		xa.GetRef(1) ^= xb.GetRef(1);
		xa.GetRef(2) ^= xb.GetRef(2);
		xa.GetRef(3) ^= xb.GetRef(3);
	}

	[Benchmark(Description = @"Unsafe")]
	public void E()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		unsafe
		{
			fixed (byte* pa = &MemoryMarshal.GetReference(a))
			fixed (byte* pb = &MemoryMarshal.GetReference(b))
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

		Span<UInt128> xa = MemoryMarshal.Cast<byte, UInt128>(a);
		ReadOnlySpan<UInt128> xb = MemoryMarshal.Cast<byte, UInt128>(b);

		xa.GetRef(0) ^= xb.GetRef(0);
		xa.GetRef(1) ^= xb.GetRef(1);
		xa.GetRef(2) ^= xb.GetRef(2);
		xa.GetRef(3) ^= xb.GetRef(3);
	}

	[Benchmark(Description = @"ulong")]
	public void G()
	{
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		Span<ulong> xa = MemoryMarshal.Cast<byte, ulong>(a);
		ReadOnlySpan<ulong> xb = MemoryMarshal.Cast<byte, ulong>(b);

		xa.GetRef(0) ^= xb.GetRef(0);
		xa.GetRef(1) ^= xb.GetRef(1);
		xa.GetRef(2) ^= xb.GetRef(2);
		xa.GetRef(3) ^= xb.GetRef(3);
		xa.GetRef(4) ^= xb.GetRef(4);
		xa.GetRef(5) ^= xb.GetRef(5);
		xa.GetRef(6) ^= xb.GetRef(6);
		xa.GetRef(7) ^= xb.GetRef(7);
	}
}
