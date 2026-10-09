using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Ciphers.Modes.Xts;

internal static class XtsTweak
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Fill(ref Vector128<byte> tweak, Span<byte> destination)
	{
		Debug.Assert(destination.Length % 16 is 0);

		Vector128<byte> currentTweak = tweak;
		int i = 0;

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported && destination.Length >= 64)
		{
			Vector128<byte> t1 = MultiplyByAlpha(currentTweak);
			Vector128<byte> t2 = MultiplyByAlpha(t1);
			Vector128<byte> t3 = MultiplyByAlpha(t2);
			Vector512<byte> lanes = Vector512.Create(Vector256.Create(currentTweak, t1), Vector256.Create(t2, t3));

			for (; i <= destination.Length - 64; i += 64)
			{
				lanes.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)i);
				lanes = MultiplyByAlphaPower(lanes, 4);
			}

			currentTweak = lanes.GetLower().GetLower();
		}
		else if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported && destination.Length >= 512)
		{
			CreatePacked8(currentTweak, out Vector256<byte> t0, out Vector256<byte> t1, out Vector256<byte> t2, out Vector256<byte> t3);

			for (; i <= destination.Length - 128; i += 128)
			{
				t0.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)i);
				t1.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 32));
				t2.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 64));
				t3.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 96));
				AdvancePacked8(ref t0, ref t1, ref t2, ref t3);
			}

			currentTweak = t0.GetLower();
		}
		else if (Pclmulqdq.IsSupported)
		{
			for (; i <= destination.Length - 128; i += 128)
			{
				currentTweak.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 0));
				MultiplyByAlphaPower(currentTweak, 1).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 16));
				MultiplyByAlphaPower(currentTweak, 2).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 32));
				MultiplyByAlphaPower(currentTweak, 3).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 48));
				MultiplyByAlphaPower(currentTweak, 4).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 64));
				MultiplyByAlphaPower(currentTweak, 5).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 80));
				MultiplyByAlphaPower(currentTweak, 6).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 96));
				MultiplyByAlphaPower(currentTweak, 7).StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)(i + 112));
				currentTweak = MultiplyByAlphaPower(currentTweak, 8);
			}
		}

		for (; i < destination.Length; i += 16)
		{
			currentTweak.StoreUnsafe(ref MemoryMarshal.GetReference(destination), (nuint)i);
			currentTweak = MultiplyByAlpha(currentTweak);
		}

		tweak = currentTweak;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void CreatePacked8(Vector128<byte> tweak, out Vector256<byte> t01, out Vector256<byte> t23, out Vector256<byte> t45, out Vector256<byte> t67)
	{
		t01 = Vector256.Create(tweak, MultiplyByAlpha(tweak));
		t23 = MultiplyByAlphaPower(t01, 2);
		t45 = MultiplyByAlphaPower(t01, 4);
		t67 = MultiplyByAlphaPower(t01, 6);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AdvancePacked8(ref Vector256<byte> t01, ref Vector256<byte> t23, ref Vector256<byte> t45, ref Vector256<byte> t67)
	{
		t01 = MultiplyByAlphaPower(t01, 8);
		t23 = MultiplyByAlphaPower(t23, 8);
		t45 = MultiplyByAlphaPower(t45, 8);
		t67 = MultiplyByAlphaPower(t67, 8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> MultiplyByAlphaPower(Vector128<byte> tweak, [ConstantExpected(Min = 1, Max = 8)] byte power)
	{
		Debug.Assert(Pclmulqdq.IsSupported);

		Vector128<ulong> carry = tweak.AsUInt64() >>> 64 - power;
		Vector128<ulong> reduction = Pclmulqdq.CarrylessMultiply(carry, Vector128.Create(0x87UL), 0x01);
		return (tweak.AsUInt64() << power ^ Sse2.ShiftLeftLogical128BitLane(carry, 8) ^ reduction).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> MultiplyByAlphaPower(Vector256<byte> tweak, [ConstantExpected(Min = 1, Max = 8)] byte power)
	{
		Vector256<ulong> carry = tweak.AsUInt64() >>> 64 - power;
		Vector256<ulong> reduction = Pclmulqdq.V256.CarrylessMultiply(carry, Vector256.Create(0x87UL), 0x01);
		return (tweak.AsUInt64() << power ^ Avx2.ShiftLeftLogical128BitLane(carry, 8) ^ reduction).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> MultiplyByAlphaPower(Vector512<byte> tweak, [ConstantExpected(Min = 1, Max = 8)] byte power)
	{
		Vector512<ulong> carry = tweak.AsUInt64() >>> 64 - power;
		Vector512<ulong> reduction = Pclmulqdq.V512.CarrylessMultiply(carry, Vector512.Create(0x87UL), 0x01);
		return (tweak.AsUInt64() << power ^ Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64() ^ reduction).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> MultiplyByAlpha(Vector128<byte> tweak)
	{
		if (Sse2.IsSupported || AdvSimd.Arm64.IsSupported)
		{
			Vector128<byte> carry = Sse2.IsSupported
				? (Sse2.Shuffle(tweak.AsInt32(), 0b00_01_00_11) >> 31).AsByte()
				: (AdvSimd.ExtractVector128(tweak.AsInt64(), tweak.AsInt64(), 1) >> 63).AsByte();
			return (tweak.AsUInt64() << 1).AsByte() ^ carry & Vector128.Create(0x87UL, 1UL).AsByte();
		}

		UInt128 value = BinaryPrimitives.ReadUInt128LittleEndian(tweak.AsReadOnlySpan());
		value = value << 1 ^ (UInt128)((Int128)value >> 127) & 0x87;
		BinaryPrimitives.WriteUInt128LittleEndian(tweak.AsSpan(), value);
		return tweak;
	}
}
