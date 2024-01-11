using BenchmarkDotNet.Attributes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

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
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Xor(Span<byte> a, Span<byte> b)
		{
			for (int i = 0; i < 16; ++i)
			{
				a[i] ^= b[i];
			}
		}
	}

	[Benchmark(Description = @"Without bounds checking")]
	public void B()
	{
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Xor(Span<byte> a, Span<byte> b)
		{
			for (int i = 0; i < 16; ++i)
			{
				a.GetRef(i) ^= b.GetRef(i);
			}
		}
	}

	[Benchmark(Description = @"Without bounds checking + unrolling")]
	public void B2()
	{
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Xor(Span<byte> a, Span<byte> b)
		{
			a.GetRef(0) ^= b.GetRef(0);
			a.GetRef(1) ^= b.GetRef(1);
			a.GetRef(2) ^= b.GetRef(2);
			a.GetRef(3) ^= b.GetRef(3);
			a.GetRef(4) ^= b.GetRef(4);
			a.GetRef(5) ^= b.GetRef(5);
			a.GetRef(6) ^= b.GetRef(6);
			a.GetRef(7) ^= b.GetRef(7);
			a.GetRef(8) ^= b.GetRef(8);
			a.GetRef(9) ^= b.GetRef(9);
			a.GetRef(10) ^= b.GetRef(10);
			a.GetRef(11) ^= b.GetRef(11);
			a.GetRef(12) ^= b.GetRef(12);
			a.GetRef(13) ^= b.GetRef(13);
			a.GetRef(14) ^= b.GetRef(14);
			a.GetRef(15) ^= b.GetRef(15);
		}
	}

	[Benchmark(Description = @"Vector128")]
	public void C()
	{
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Xor(Span<byte> a, Span<byte> b)
		{
			Vector128<byte> v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(a));
			Vector128<byte> v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(b));
			(v0 ^ v1).CopyTo(a);
		}
	}

	[Benchmark(Description = @"SSE2")]
	public void D()
	{
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static unsafe void Xor(Span<byte> a, Span<byte> b)
		{
			Vector128<byte> v0 = Sse2.LoadVector128((byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(a)));
			Vector128<byte> v1 = Sse2.LoadVector128((byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(b)));
			Sse2.Xor(v0, v1).CopyTo(a);
		}
	}

	[Benchmark(Description = @"Unsafe")]
	public void E()
	{
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static unsafe void Xor(Span<byte> a, Span<byte> b)
		{
			fixed (byte* pa = &MemoryMarshal.GetReference(a))
			fixed (byte* pb = &MemoryMarshal.GetReference(b))
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
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static unsafe void Xor(Span<byte> a, Span<byte> b)
		{
			fixed (byte* pa = &MemoryMarshal.GetReference(a))
			fixed (byte* pb = &MemoryMarshal.GetReference(b))
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
}
