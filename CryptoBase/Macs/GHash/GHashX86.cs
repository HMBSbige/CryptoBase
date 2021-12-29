using CryptoBase.Abstractions;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Macs.GHash;

public class GHashX86 : IMac
{
	public string Name => @"GHash";

	public int Length => 16;

	public const int KeySize = 16;
	public const int BlockSize = 16;

	private readonly Vector128<byte> _key;
	private Vector128<byte> _buffer;

	public unsafe GHashX86(ReadOnlySpan<byte> key)
	{
		if (key.Length < KeySize)
		{
			throw new ArgumentException(@"Key length must be 16 bytes", nameof(key));
		}

		fixed (byte* p = key)
		{
			_key = Sse2.LoadVector128(p).Reverse();
		}

		Reset();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private unsafe void GFMul(ReadOnlySpan<byte> x)
	{
		var a = _key.AsUInt64();
		Vector128<ulong> b;

		fixed (byte* p = x)
		{
			var t = Sse2.LoadVector128(p);
			b = t.Reverse().AsUInt64();
		}

		b = Sse2.Xor(b.AsByte(), _buffer).AsUInt64();

		var tmp3 = Pclmulqdq.CarrylessMultiply(a, b, 0x00).AsUInt32();
		var tmp4 = Pclmulqdq.CarrylessMultiply(a, b, 0x10).AsUInt32();
		var tmp5 = Pclmulqdq.CarrylessMultiply(a, b, 0x01).AsUInt32();
		var tmp6 = Pclmulqdq.CarrylessMultiply(a, b, 0x11).AsUInt32();

		tmp4 = Sse2.Xor(tmp4, tmp5);
		tmp5 = Sse2.ShiftLeftLogical128BitLane(tmp4, 8);
		tmp4 = Sse2.ShiftRightLogical128BitLane(tmp4, 8);
		tmp3 = Sse2.Xor(tmp3, tmp5);
		tmp6 = Sse2.Xor(tmp6, tmp4);

		var tmp7 = Sse2.ShiftRightLogical(tmp3, 31);
		var tmp8 = Sse2.ShiftRightLogical(tmp6, 31);
		tmp3 = Sse2.ShiftLeftLogical(tmp3, 1);
		tmp6 = Sse2.ShiftLeftLogical(tmp6, 1);
		var tmp9 = Sse2.ShiftRightLogical128BitLane(tmp7, 12);
		tmp8 = Sse2.ShiftLeftLogical128BitLane(tmp8, 4);
		tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 4);
		tmp3 = Sse2.Or(tmp3, tmp7);
		tmp6 = Sse2.Or(tmp6, tmp8);
		tmp6 = Sse2.Or(tmp6, tmp9);
		tmp7 = Sse2.ShiftLeftLogical(tmp3, 31);
		tmp8 = Sse2.ShiftLeftLogical(tmp3, 30);
		tmp9 = Sse2.ShiftLeftLogical(tmp3, 25);
		tmp7 = Sse2.Xor(tmp7, tmp8);
		tmp7 = Sse2.Xor(tmp7, tmp9);
		tmp8 = Sse2.ShiftRightLogical128BitLane(tmp7, 4);
		tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 12);
		tmp3 = Sse2.Xor(tmp3, tmp7);
		var tmp2 = Sse2.ShiftRightLogical(tmp3, 1);
		tmp4 = Sse2.ShiftRightLogical(tmp3, 2);
		tmp5 = Sse2.ShiftRightLogical(tmp3, 7);
		tmp2 = Sse2.Xor(tmp2, tmp4);
		tmp2 = Sse2.Xor(tmp2, tmp5);
		tmp2 = Sse2.Xor(tmp2, tmp8);
		tmp3 = Sse2.Xor(tmp3, tmp2);
		tmp6 = Sse2.Xor(tmp6, tmp3);

		_buffer = tmp6.AsByte();
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		while (source.Length >= BlockSize)
		{
			GFMul(source);
			source = source[BlockSize..];
		}

		if (source.IsEmpty)
		{
			return;
		}

		Span<byte> block = stackalloc byte[BlockSize];
		source.CopyTo(block);
		GFMul(block);
	}

	public unsafe void GetMac(Span<byte> destination)
	{
		fixed (byte* p = destination)
		{
			Sse2.Store(p, _buffer.Reverse());
		}

		Reset();
	}

	public void Reset()
	{
		_buffer = default;
	}

	public void Dispose() { }
}
