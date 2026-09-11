namespace CryptoBase.Hashes.Sha256;

internal partial struct Sha256Core
{
	[SkipLocalsInit]
	private void ProcessBlocksAdvSimd(ReadOnlySpan<byte> source)
	{
		Debug.Assert(AdvSimd.Arm64.IsSupported);
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		ref byte block = ref source.GetReference();
		int remainingLength = source.Length;
		uint h0 = _h0;
		uint h1 = _h1;
		uint h2 = _h2;
		uint h3 = _h3;
		uint h4 = _h4;
		uint h5 = _h5;
		uint h6 = _h6;
		uint h7 = _h7;
		Vector128<uint> zero = Vector128<uint>.Zero;
		ref uint roundConstant0 = ref RoundConstants.GetReference();
		Unsafe.SkipInit(out InlineArray4<uint> roundInputBuffer);
		ref uint roundInput0 = ref roundInputBuffer[0];

		do
		{
			Vector128<uint> words0 = LoadArm64Words(ref block);
			Vector128<uint> words1 = LoadArm64Words(ref Unsafe.Add(ref block, 16));
			Vector128<uint> words2 = LoadArm64Words(ref Unsafe.Add(ref block, 32));
			Vector128<uint> words3 = LoadArm64Words(ref Unsafe.Add(ref block, 48));
			uint a = h0;
			uint b = h1;
			uint c = h2;
			uint d = h3;
			uint e = h4;
			uint f = h5;
			uint g = h6;
			uint h = h7;
			uint sigma0Carry = 0;
			uint bcXor = b ^ c;

			StoreRoundInputAdvSimd(words0, 0, ref roundInput0);
			CompressFourRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref roundInput0, ref sigma0Carry, ref bcXor);
			StoreRoundInputAdvSimd(words1, 4, ref roundInput0);
			CompressFourRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref roundInput0, ref sigma0Carry, ref bcXor);
			StoreRoundInputAdvSimd(words2, 8, ref roundInput0);
			CompressFourRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref roundInput0, ref sigma0Carry, ref bcXor);
			StoreRoundInputAdvSimd(words3, 12, ref roundInput0);

			for (int round = 16; round < 64; round += 16)
			{
				LoadFourRoundConstantsAdvSimd(ref roundConstant0, round, out Vector128<uint> roundConstants0, out Vector128<uint> roundConstants1, out Vector128<uint> roundConstants2, out Vector128<uint> roundConstants3);
				words0 = UpdateScheduleAndCompressFourRoundsAdvSimd(words0, words1, words2, words3, ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, roundConstants0, ref roundInput0, ref sigma0Carry, ref bcXor, zero);
				words1 = UpdateScheduleAndCompressFourRoundsAdvSimd(words1, words2, words3, words0, ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, roundConstants1, ref roundInput0, ref sigma0Carry, ref bcXor, zero);
				words2 = UpdateScheduleAndCompressFourRoundsAdvSimd(words2, words3, words0, words1, ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, roundConstants2, ref roundInput0, ref sigma0Carry, ref bcXor, zero);
				words3 = UpdateScheduleAndCompressFourRoundsAdvSimd(words3, words0, words1, words2, ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, roundConstants3, ref roundInput0, ref sigma0Carry, ref bcXor, zero);
			}

			CompressFourRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref roundInput0, ref sigma0Carry, ref bcXor);
			a += sigma0Carry;

			h0 += a;
			h1 += b;
			h2 += c;
			h3 += d;
			h4 += e;
			h5 += f;
			h6 += g;
			h7 += h;
			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);

		_h0 = h0;
		_h1 = h1;
		_h2 = h2;
		_h3 = h3;
		_h4 = h4;
		_h5 = h5;
		_h6 = h6;
		_h7 = h7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void LoadFourRoundConstantsAdvSimd(ref uint source, int offset, out Vector128<uint> roundConstants0, out Vector128<uint> roundConstants1, out Vector128<uint> roundConstants2, out Vector128<uint> roundConstants3)
	{
		uint* address = (uint*)Unsafe.AsPointer(ref Unsafe.Add(ref source, offset));
		(roundConstants0, roundConstants1) = AdvSimd.Arm64.LoadPairVector128(address);
		(roundConstants2, roundConstants3) = AdvSimd.Arm64.LoadPairVector128(address + 8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> UpdateScheduleAndCompressFourRoundsAdvSimd
	(
		Vector128<uint> words0, Vector128<uint> words1, Vector128<uint> words2, Vector128<uint> words3,
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		Vector128<uint> roundConstants,
		ref uint roundInput0,
		ref uint sigma0Carry,
		ref uint bcXor,
		Vector128<uint> zero
	)
	{
		Vector128<uint> sigma0Input = AdvSimd.ExtractVector128(words0, words1, 1);
		Vector128<uint> result = words0 + AdvSimd.ExtractVector128(words2, words3, 1);
		Vector128<uint> sigma0Rotate7 = AdvSimd.ShiftRightAndInsert(sigma0Input << 25, sigma0Input, 7);

		CompressDeferredRound(ref a, ref b, ref d, ref e, ref f, ref g, ref h, roundInput0, ref sigma0Carry, ref bcXor);

		Vector128<uint> sigma0Rotate18 = AdvSimd.ShiftRightAndInsert(sigma0Input << 14, sigma0Input, 18);
		Vector128<uint> sigma0Shift3 = sigma0Input >>> 3;
		result += sigma0Shift3 ^ sigma0Rotate7 ^ sigma0Rotate18;

		CompressDeferredRound(ref h, ref a, ref c, ref d, ref e, ref f, ref g, Unsafe.Add(ref roundInput0, 1), ref sigma0Carry, ref bcXor);

		Vector128<uint> sigma1Input = AdvSimd.ExtractVector128(words3, zero, 2);
		result += SmallSigma1AdvSimd(sigma1Input);

		CompressDeferredRound(ref g, ref h, ref b, ref c, ref d, ref e, ref f, Unsafe.Add(ref roundInput0, 2), ref sigma0Carry, ref bcXor);

		Vector128<uint> dependentInput = AdvSimd.ExtractVector128(zero, result, 2);
		result += SmallSigma1AdvSimd(dependentInput);

		CompressDeferredRound(ref f, ref g, ref a, ref b, ref c, ref d, ref e, Unsafe.Add(ref roundInput0, 3), ref sigma0Carry, ref bcXor);

		StoreRoundInputAdvSimd(result, roundConstants, ref roundInput0);
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> SmallSigma1AdvSimd(Vector128<uint> value)
	{
		Vector128<uint> rotate17 = AdvSimd.ShiftRightAndInsert(value << 15, value, 17);
		Vector128<uint> rotate19 = AdvSimd.ShiftRightAndInsert(value << 13, value, 19);
		return value >>> 10 ^ rotate17 ^ rotate19;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRoundInputAdvSimd(Vector128<uint> words, int round, ref uint roundInput0)
	{
		ref uint roundConstant0 = ref RoundConstants.GetReference();
		StoreRoundInputAdvSimd(words, Vector128.LoadUnsafe(ref roundConstant0, (uint)round), ref roundInput0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRoundInputAdvSimd(Vector128<uint> words, Vector128<uint> roundConstants, ref uint roundInput0)
	{
		Vector128<uint> roundInput = words + roundConstants;
		roundInput.StoreUnsafe(ref roundInput0);
	}
}
