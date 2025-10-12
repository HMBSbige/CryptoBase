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
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Xor(Span<byte> a, Span<byte> b)
		{
			for (int i = 0; i < 64; ++i)
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
			for (int i = 0; i < 64; ++i)
			{
				a.GetRef(i) ^= b.GetRef(i);
			}
		}
	}

	[Benchmark(Description = @"Vector512")]
	public void C()
	{
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Xor(Span<byte> a, Span<byte> b)
		{
			Vector512<byte> v0 = Unsafe.ReadUnaligned<Vector512<byte>>(ref MemoryMarshal.GetReference(a));
			Vector512<byte> v1 = Unsafe.ReadUnaligned<Vector512<byte>>(ref MemoryMarshal.GetReference(b));
			(v0 ^ v1).CopyTo(a);
		}
	}


	[Benchmark(Description = @"Vector256")]
	public void D()
	{
		Xor(_a.Span, _b.Span);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Xor(Span<byte> a, Span<byte> b)
		{
			Vector256<byte> va0 = Unsafe.ReadUnaligned<Vector256<byte>>(ref MemoryMarshal.GetReference(a));
			Vector256<byte> va1 = Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref MemoryMarshal.GetReference(a), 32));
			Vector256<byte> vb0 = Unsafe.ReadUnaligned<Vector256<byte>>(ref MemoryMarshal.GetReference(b));
			Vector256<byte> vb1 = Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref MemoryMarshal.GetReference(b), 32));

			(va0 ^ vb0).CopyTo(a);
			(va1 ^ vb1).CopyTo(a[32..]);
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
				for (int i = 0; i < 64; ++i)
				{
					*(pa + i) ^= *(pb + i);
				}
			}
		}
	}
}
