namespace CryptoBase.Hashes.Sha256;

internal partial struct Sha256Core
{
	[SkipLocalsInit]
	private void ProcessBlocksAvx2(ReadOnlySpan<byte> source)
	{
		Debug.Assert(Avx2.IsSupported);
		Debug.Assert(source.Length >= 2 * BlockSizeInBytes);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		Unsafe.SkipInit(out InlineArray16<uint> schedule0);
		Unsafe.SkipInit(out InlineArray64<uint> schedule1);
		ref byte sourceRef = ref source.GetReference();
		int remainingLength = source.Length;

		// Buffer the second block's round inputs until the first block updates the hash state.
		while (remainingLength >= 2 * BlockSizeInBytes)
		{
			Vector256<uint> words0 = LoadWordsAvx2(ref sourceRef, 0);
			Vector256<uint> words1 = LoadWordsAvx2(ref sourceRef, 16);
			Vector256<uint> words2 = LoadWordsAvx2(ref sourceRef, 32);
			Vector256<uint> words3 = LoadWordsAvx2(ref sourceRef, 48);

			uint a = _h0;
			uint b = _h1;
			uint c = _h2;
			uint d = _h3;
			uint e = _h4;
			uint f = _h5;
			uint g = _h6;
			uint h = _h7;
			uint sigma0Carry = 0;
			uint bcXor = b ^ c;

			StoreRoundInputAvx2(words0, ref schedule0, ref schedule1, 0, 0);
			StoreRoundInputAvx2(words1, ref schedule0, ref schedule1, 4, 4);
			StoreRoundInputAvx2(words2, ref schedule0, ref schedule1, 8, 8);
			StoreRoundInputAvx2(words3, ref schedule0, ref schedule1, 12, 12);

			for (int round = 16; round < 64; round += 16)
			{
				words0 = UpdateScheduleAndCompressFourRounds(words0, words1, words2, words3, ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref schedule1, 0, round, ref sigma0Carry, ref bcXor);
				words1 = UpdateScheduleAndCompressFourRounds(words1, words2, words3, words0, ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref schedule0, ref schedule1, 4, round + 4, ref sigma0Carry, ref bcXor);
				words2 = UpdateScheduleAndCompressFourRounds(words2, words3, words0, words1, ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref schedule1, 8, round + 8, ref sigma0Carry, ref bcXor);
				words3 = UpdateScheduleAndCompressFourRounds(words3, words0, words1, words2, ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref schedule0, ref schedule1, 12, round + 12, ref sigma0Carry, ref bcXor);
			}

			CompressFourRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0[0], ref sigma0Carry, ref bcXor);
			CompressFourRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref schedule0[4], ref sigma0Carry, ref bcXor);
			CompressFourRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0[8], ref sigma0Carry, ref bcXor);
			CompressFourRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref schedule0[12], ref sigma0Carry, ref bcXor);
			a += sigma0Carry;

			_h0 += a;
			_h1 += b;
			_h2 += c;
			_h3 += d;
			_h4 += e;
			_h5 += f;
			_h6 += g;
			_h7 += h;

			CompressSchedule(ref schedule1[0]);
			sourceRef = ref Unsafe.Add(ref sourceRef, 2 * BlockSizeInBytes);
			remainingLength -= 2 * BlockSizeInBytes;
		}

		if (remainingLength is not 0)
		{
			ProcessBlocksSoftware(MemoryMarshal.CreateReadOnlySpan(ref sourceRef, remainingLength));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> LoadWordsAvx2(ref byte source, int offset)
	{
		Vector256<byte> words = Vector256.Create(Vector128.LoadUnsafe(ref source, (nuint)offset), Vector128.LoadUnsafe(ref source, (nuint)(BlockSizeInBytes + offset)));
		return words.ReverseEndianness32().AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> UpdateScheduleAndCompressFourRounds
	(
		Vector256<uint> words0, Vector256<uint> words1, Vector256<uint> words2, Vector256<uint> words3,
		ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h,
		ref InlineArray16<uint> schedule0, ref InlineArray64<uint> schedule1,
		int scheduleOffset,
		int round,
		ref uint sigma0Carry,
		ref uint bcXor
	)
	{
		ref uint roundInput0 = ref schedule0[scheduleOffset];
		Vector256<uint> sigma0Input = Avx2.AlignRight(words1, words0, 4);
		Vector256<uint> wordsMinus7 = Avx2.AlignRight(words3, words2, 4);
		Vector256<uint> sigma0Rotate7 = sigma0Input.RotateRightUInt32(7);

		CompressDeferredRound(ref a, ref b, ref d, ref e, ref f, ref g, ref h, roundInput0, ref sigma0Carry, ref bcXor);

		Vector256<uint> sigma0Rotate18 = sigma0Input.RotateRightUInt32(18);
		Vector256<uint> sigma0Shift3 = sigma0Input >>> 3;
		Vector256<uint> result = words0 + wordsMinus7 + (sigma0Shift3 ^ sigma0Rotate7 ^ sigma0Rotate18);

		CompressDeferredRound(ref h, ref a, ref c, ref d, ref e, ref f, ref g, Unsafe.Add(ref roundInput0, 1), ref sigma0Carry, ref bcXor);

		Vector256<uint> sigma1Input = Avx2.ShiftRightLogical128BitLane(words3, 8);
		Vector256<uint> sigma1Rotate17 = sigma1Input.RotateRightUInt32(17);
		Vector256<uint> sigma1Rotate19 = sigma1Input.RotateRightUInt32(19);
		Vector256<uint> sigma1Shift10 = sigma1Input >>> 10;
		result += sigma1Shift10 ^ sigma1Rotate17 ^ sigma1Rotate19;

		CompressDeferredRound(ref g, ref h, ref b, ref c, ref d, ref e, ref f, Unsafe.Add(ref roundInput0, 2), ref sigma0Carry, ref bcXor);

		Vector256<uint> dependentRotate17 = result.RotateRightUInt32(17);
		Vector256<uint> dependentRotate19 = result.RotateRightUInt32(19);
		Vector256<uint> dependentShift10 = result >>> 10;
		Vector256<uint> dependentSigma1 = dependentShift10 ^ dependentRotate17 ^ dependentRotate19;
		result += Avx2.ShiftLeftLogical128BitLane(dependentSigma1, 8);

		CompressDeferredRound(ref f, ref g, ref a, ref b, ref c, ref d, ref e, Unsafe.Add(ref roundInput0, 3), ref sigma0Carry, ref bcXor);

		StoreRoundInputAvx2(result, ref schedule0, ref schedule1, scheduleOffset, round);
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRoundInputAvx2(Vector256<uint> words, ref InlineArray16<uint> schedule0, ref InlineArray64<uint> schedule1, int scheduleOffset, int round)
	{
		ref uint roundConstant0 = ref RoundConstants.GetReference();
		Vector128<uint> constants128 = Vector128.LoadUnsafe(ref roundConstant0, (uint)round);
		Vector256<uint> roundInput = words + Vector256.Create(constants128);
		roundInput.GetLower().StoreUnsafe(ref schedule0[scheduleOffset]);
		roundInput.GetUpper().StoreUnsafe(ref schedule1[round]);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void CompressSchedule(ref uint roundInput0)
	{
		uint a = _h0;
		uint b = _h1;
		uint c = _h2;
		uint d = _h3;
		uint e = _h4;
		uint f = _h5;
		uint g = _h6;
		uint h = _h7;
		uint sigma0Carry = 0;
		uint bcXor = b ^ c;

		for (nuint i = 0; i < 64; i += 8)
		{
			ref uint currentRoundInput = ref Unsafe.Add(ref roundInput0, i);
			CompressFourRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref currentRoundInput, ref sigma0Carry, ref bcXor);
			CompressFourRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref Unsafe.Add(ref currentRoundInput, 4), ref sigma0Carry, ref bcXor);
		}

		a += sigma0Carry;

		_h0 += a;
		_h1 += b;
		_h2 += c;
		_h3 += d;
		_h4 += e;
		_h5 += f;
		_h6 += g;
		_h7 += h;
	}
}
