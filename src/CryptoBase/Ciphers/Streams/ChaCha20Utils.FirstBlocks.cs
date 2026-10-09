namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool ShouldDerivePoly1305KeyAndKeyStream(int length)
	{
		// Narrower x86 targets keep the separate path after measured regressions.
		if (!Vector512.IsHardwareAccelerated && !AdvSimd.Arm64.IsSupported)
		{
			return false;
		}

		int vectorizedLength = AdvSimd.Arm64.IsSupported ? 128 : 256;
		return (uint)(length - 1) < (uint)(vectorizedLength - 1);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void DerivePoly1305KeyAndKeyStream(ref uint stateRef, Span<byte> poly1305Key, Span<byte> keyStream)
	{
		Debug.Assert(GetCounter(ref stateRef) is 0 && poly1305Key.Length is 32 && keyStream.Length is 64);
		Vector128<uint> row0 = SnuffleCipher.LoadStateRow(ref stateRef, 0);
		Vector128<uint> row1 = SnuffleCipher.LoadStateRow(ref stateRef, 4);
		Vector128<uint> row2 = SnuffleCipher.LoadStateRow(ref stateRef, 8);
		Vector128<uint> row3 = SnuffleCipher.LoadStateRow(ref stateRef, 12);

		if (Avx2.IsSupported)
		{
			FirstBlocksAvx2(row0, row1, row2, row3, ref MemoryMarshal.GetReference(poly1305Key), ref MemoryMarshal.GetReference(keyStream));
			return;
		}

		FirstBlocksVector128(row0, row1, row2, row3, ref MemoryMarshal.GetReference(poly1305Key), ref MemoryMarshal.GetReference(keyStream));
	}

	// Block 0 in the low lanes and block 1 in the high lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FirstBlocksAvx2(Vector128<uint> row0, Vector128<uint> row1, Vector128<uint> row2, Vector128<uint> row3, ref byte poly1305Key, ref byte keyStream)
	{
		Vector256<uint> initial0 = Vector256.Create(row0);
		Vector256<uint> initial1 = Vector256.Create(row1);
		Vector256<uint> initial2 = Vector256.Create(row2);
		Vector256<uint> initial3 = Vector256.Create(row3).AddUInt32LE01();
		Vector256<uint> a = initial0;
		Vector256<uint> b = initial1;
		Vector256<uint> c = initial2;
		Vector256<uint> d = initial3;

		for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
		{
			QuarterRound(ref a, ref b, ref c, ref d);
			a = Avx2.Shuffle(a, 0b10_01_00_11);
			c = Avx2.Shuffle(c, 0b00_11_10_01);
			d = Avx2.Shuffle(d, 0b01_00_11_10);
			QuarterRound(ref a, ref b, ref c, ref d);
			a = Avx2.Shuffle(a, 0b00_11_10_01);
			c = Avx2.Shuffle(c, 0b10_01_00_11);
			d = Avx2.Shuffle(d, 0b01_00_11_10);
		}

		a += initial0;
		b += initial1;
		c += initial2;
		d += initial3;
		Vector256.Create(a.GetLower(), b.GetLower()).AsByte().StoreUnsafe(ref poly1305Key);
		Vector256.Create(a.GetUpper(), b.GetUpper()).AsByte().StoreUnsafe(ref keyStream);
		Vector256.Create(c.GetUpper(), d.GetUpper()).AsByte().StoreUnsafe(ref keyStream, 32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FirstBlocksVector128(Vector128<uint> row0, Vector128<uint> row1, Vector128<uint> row2, Vector128<uint> row3, ref byte poly1305Key, ref byte keyStream)
	{
		Vector128<uint> next3 = row3 + Vector128.CreateScalar(1u);
		Vector128<uint> a0 = row0, a1 = row1, a2 = row2, a3 = row3;
		Vector128<uint> b0 = row0, b1 = row1, b2 = row2, b3 = next3;

		for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
		{
			QuarterRoundLocal(ref a0, ref a1, ref a2, ref a3);
			QuarterRoundLocal(ref b0, ref b1, ref b2, ref b3);
			a0 = a0.RotateWordsLeft(3);
			a2 = a2.RotateWordsLeft(1);
			a3 = a3.RotateWordsLeft(2);
			b0 = b0.RotateWordsLeft(3);
			b2 = b2.RotateWordsLeft(1);
			b3 = b3.RotateWordsLeft(2);
			QuarterRoundLocal(ref a0, ref a1, ref a2, ref a3);
			QuarterRoundLocal(ref b0, ref b1, ref b2, ref b3);
			a0 = a0.RotateWordsLeft(1);
			a2 = a2.RotateWordsLeft(3);
			a3 = a3.RotateWordsLeft(2);
			b0 = b0.RotateWordsLeft(1);
			b2 = b2.RotateWordsLeft(3);
			b3 = b3.RotateWordsLeft(2);
		}

		(a0 + row0).AsByte().StoreUnsafe(ref poly1305Key);
		(a1 + row1).AsByte().StoreUnsafe(ref poly1305Key, 16);
		(b0 + row0).AsByte().StoreUnsafe(ref keyStream);
		(b1 + row1).AsByte().StoreUnsafe(ref keyStream, 16);
		(b2 + row2).AsByte().StoreUnsafe(ref keyStream, 32);
		(b3 + next3).AsByte().StoreUnsafe(ref keyStream, 48);
	}
}
