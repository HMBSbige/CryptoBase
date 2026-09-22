namespace CryptoBase.Hashes.Sha512;

internal partial struct Sha512Core
{
	private static readonly Vector256<byte> BigEndianShuffle256 = Vector256.Create(VectorEndianExtensions.ReverseEndianness64Mask128);

	private void ProcessBlocksAvx2(ReadOnlySpan<byte> source)
	{
		Debug.Assert(Avx2.IsSupported);
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		if (!X86Base.X64.IsSupported)
		{
			ProcessBlocksAvx2Single(source);
			return;
		}

		int pairLength = source.Length & ~(2 * BlockSizeInBytes - 1);

		if (pairLength is not 0)
		{
			ProcessBlockPairsAvx2(source.Slice(0, pairLength));
			source = source.Slice(pairLength);
		}

		if (!source.IsEmpty)
		{
			if (Avx512F.VL.IsSupported)
			{
				ProcessBlocksAvx2Single(source);
			}
			else
			{
				ProcessBlocksSoftware(source);
			}
		}
	}

	[SkipLocalsInit]
	private void ProcessBlockPairsAvx2(ReadOnlySpan<byte> source)
	{
		Unsafe.SkipInit(out Sha512Schedule schedule1);
		ref byte sourceRef = ref source.GetReference();
		ref byte sourceEnd = ref Unsafe.Add(ref sourceRef, (nuint)source.Length);
		ref ulong schedule10 = ref schedule1[0];

		do
		{
			ref ulong roundConstant0 = ref RoundConstants.GetReference();
			Vector256<ulong> words0 = LoadWordPairAvx2(ref sourceRef, 0);
			Vector256<ulong> words1 = LoadWordPairAvx2(ref sourceRef, 16);
			Vector256<ulong> words2 = LoadWordPairAvx2(ref sourceRef, 32);
			Vector256<ulong> words3 = LoadWordPairAvx2(ref sourceRef, 48);
			Vector256<ulong> words4 = LoadWordPairAvx2(ref sourceRef, 64);
			Vector256<ulong> words5 = LoadWordPairAvx2(ref sourceRef, 80);
			Vector256<ulong> words6 = LoadWordPairAvx2(ref sourceRef, 96);
			Vector256<ulong> words7 = LoadWordPairAvx2(ref sourceRef, 112);
			ulong a = _h0;
			ulong b = _h1;
			ulong c = _h2;
			ulong d = _h3;
			ulong e = _h4;
			ulong f = _h5;
			ulong g = _h6;
			ulong h = _h7;
			ulong sigma0Carry = 0;
			ulong bcXor = b ^ c;

			for (nuint round = 0; round < 64; round += 16)
			{
				Vector256<ulong> constants0 = Vector256.LoadUnsafe(ref roundConstant0, round);
				Vector256<ulong> constants1 = Vector256.LoadUnsafe(ref roundConstant0, round + 4);
				Vector256<ulong> constants2 = Vector256.LoadUnsafe(ref roundConstant0, round + 8);
				Vector256<ulong> constants3 = Vector256.LoadUnsafe(ref roundConstant0, round + 12);
				Vector128<ulong> roundInput = StoreSecondBlockRoundInputAvx2(words0, ref schedule10, constants0.GetLower(), round);
				words0 = UpdateSchedulePairAvx2(words0, words1, words4, words5, words7);
				CompressTwoRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, roundInput, ref sigma0Carry, ref bcXor);
				roundInput = StoreSecondBlockRoundInputAvx2(words1, ref schedule10, constants0.GetUpper(), round + 2);
				words1 = UpdateSchedulePairAvx2(words1, words2, words5, words6, words0);
				CompressTwoRounds(ref g, ref h, ref a, ref b, ref c, ref d, ref e, ref f, roundInput, ref sigma0Carry, ref bcXor);
				roundInput = StoreSecondBlockRoundInputAvx2(words2, ref schedule10, constants1.GetLower(), round + 4);
				words2 = UpdateSchedulePairAvx2(words2, words3, words6, words7, words1);
				CompressTwoRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, roundInput, ref sigma0Carry, ref bcXor);
				roundInput = StoreSecondBlockRoundInputAvx2(words3, ref schedule10, constants1.GetUpper(), round + 6);
				words3 = UpdateSchedulePairAvx2(words3, words4, words7, words0, words2);
				CompressTwoRounds(ref c, ref d, ref e, ref f, ref g, ref h, ref a, ref b, roundInput, ref sigma0Carry, ref bcXor);
				roundInput = StoreSecondBlockRoundInputAvx2(words4, ref schedule10, constants2.GetLower(), round + 8);
				words4 = UpdateSchedulePairAvx2(words4, words5, words0, words1, words3);
				CompressTwoRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, roundInput, ref sigma0Carry, ref bcXor);
				roundInput = StoreSecondBlockRoundInputAvx2(words5, ref schedule10, constants2.GetUpper(), round + 10);
				words5 = UpdateSchedulePairAvx2(words5, words6, words1, words2, words4);
				CompressTwoRounds(ref g, ref h, ref a, ref b, ref c, ref d, ref e, ref f, roundInput, ref sigma0Carry, ref bcXor);
				roundInput = StoreSecondBlockRoundInputAvx2(words6, ref schedule10, constants3.GetLower(), round + 12);
				words6 = UpdateSchedulePairAvx2(words6, words7, words2, words3, words5);
				CompressTwoRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, roundInput, ref sigma0Carry, ref bcXor);
				roundInput = StoreSecondBlockRoundInputAvx2(words7, ref schedule10, constants3.GetUpper(), round + 14);
				words7 = UpdateSchedulePairAvx2(words7, words0, words3, words4, words6);
				CompressTwoRounds(ref c, ref d, ref e, ref f, ref g, ref h, ref a, ref b, roundInput, ref sigma0Carry, ref bcXor);
			}

			Vector256<ulong> constants4 = Vector256.LoadUnsafe(ref roundConstant0, 64);
			Vector256<ulong> constants5 = Vector256.LoadUnsafe(ref roundConstant0, 68);
			Vector256<ulong> constants6 = Vector256.LoadUnsafe(ref roundConstant0, 72);
			Vector256<ulong> constants7 = Vector256.LoadUnsafe(ref roundConstant0, 76);
			CompressTwoRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, StoreSecondBlockRoundInputAvx2(words0, ref schedule10, constants4.GetLower(), 64), ref sigma0Carry, ref bcXor);
			CompressTwoRounds(ref g, ref h, ref a, ref b, ref c, ref d, ref e, ref f, StoreSecondBlockRoundInputAvx2(words1, ref schedule10, constants4.GetUpper(), 66), ref sigma0Carry, ref bcXor);
			CompressTwoRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, StoreSecondBlockRoundInputAvx2(words2, ref schedule10, constants5.GetLower(), 68), ref sigma0Carry, ref bcXor);
			CompressTwoRounds(ref c, ref d, ref e, ref f, ref g, ref h, ref a, ref b, StoreSecondBlockRoundInputAvx2(words3, ref schedule10, constants5.GetUpper(), 70), ref sigma0Carry, ref bcXor);
			CompressTwoRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, StoreSecondBlockRoundInputAvx2(words4, ref schedule10, constants6.GetLower(), 72), ref sigma0Carry, ref bcXor);
			CompressTwoRounds(ref g, ref h, ref a, ref b, ref c, ref d, ref e, ref f, StoreSecondBlockRoundInputAvx2(words5, ref schedule10, constants6.GetUpper(), 74), ref sigma0Carry, ref bcXor);
			CompressTwoRounds(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, StoreSecondBlockRoundInputAvx2(words6, ref schedule10, constants7.GetLower(), 76), ref sigma0Carry, ref bcXor);
			CompressTwoRounds(ref c, ref d, ref e, ref f, ref g, ref h, ref a, ref b, StoreSecondBlockRoundInputAvx2(words7, ref schedule10, constants7.GetUpper(), 78), ref sigma0Carry, ref bcXor);
			a += sigma0Carry;

			_h0 += a;
			_h1 += b;
			_h2 += c;
			_h3 += d;
			_h4 += e;
			_h5 += f;
			_h6 += g;
			_h7 += h;
			CompressRoundInputs(ref schedule10);
			sourceRef = ref Unsafe.Add(ref sourceRef, (nuint)(2 * BlockSizeInBytes));
		} while (Unsafe.IsAddressLessThan(ref sourceRef, ref sourceEnd));
	}

	[SkipLocalsInit]
	private void ProcessBlocksAvx2Single(ReadOnlySpan<byte> source)
	{
		Debug.Assert(Avx2.IsSupported);
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		Unsafe.SkipInit(out InlineArray16<ulong> schedule);
		ref byte sourceRef = ref source.GetReference();
		ref byte sourceEnd = ref Unsafe.Add(ref sourceRef, (nuint)source.Length);
		ref ulong schedule0 = ref schedule[0];

		do
		{
			Vector256<ulong> words0 = LoadWordsAvx2(ref sourceRef, 0);
			Vector256<ulong> words1 = LoadWordsAvx2(ref sourceRef, 32);
			Vector256<ulong> words2 = LoadWordsAvx2(ref sourceRef, 64);
			Vector256<ulong> words3 = LoadWordsAvx2(ref sourceRef, 96);
			StoreRoundInputAvx2(words0, ref schedule0, 0, 0);
			StoreRoundInputAvx2(words1, ref schedule0, 4, 4);
			StoreRoundInputAvx2(words2, ref schedule0, 8, 8);
			StoreRoundInputAvx2(words3, ref schedule0, 12, 12);

			ulong a = _h0;
			ulong b = _h1;
			ulong c = _h2;
			ulong d = _h3;
			ulong e = _h4;
			ulong f = _h5;
			ulong g = _h6;
			ulong h = _h7;
			ulong sigma0Carry = 0;
			ulong bcXor = b ^ c;

			for (nuint i = 0; i < 80; i += 8)
			{
				if (i >= 16)
				{
					if ((i & 8) is 0)
					{
						words0 = UpdateScheduleAvx2(words0, words1, words2, words3);
						words1 = UpdateScheduleAvx2(words1, words2, words3, words0);
						StoreRoundInputAvx2(words0, ref schedule0, 0, i);
						StoreRoundInputAvx2(words1, ref schedule0, 4, i + 4);
					}
					else
					{
						words2 = UpdateScheduleAvx2(words2, words3, words0, words1);
						words3 = UpdateScheduleAvx2(words3, words0, words1, words2);
						StoreRoundInputAvx2(words2, ref schedule0, 8, i);
						StoreRoundInputAvx2(words3, ref schedule0, 12, i + 4);
					}
				}

				ref ulong word0 = ref Unsafe.Add(ref schedule0, i & 15);
				CompressDeferredRound(ref a, ref b, ref d, ref e, ref f, ref g, ref h, word0, ref sigma0Carry, ref bcXor);
				CompressDeferredRound(ref h, ref a, ref c, ref d, ref e, ref f, ref g, Unsafe.Add(ref word0, 1), ref sigma0Carry, ref bcXor);
				CompressDeferredRound(ref g, ref h, ref b, ref c, ref d, ref e, ref f, Unsafe.Add(ref word0, 2), ref sigma0Carry, ref bcXor);
				CompressDeferredRound(ref f, ref g, ref a, ref b, ref c, ref d, ref e, Unsafe.Add(ref word0, 3), ref sigma0Carry, ref bcXor);
				CompressDeferredRound(ref e, ref f, ref h, ref a, ref b, ref c, ref d, Unsafe.Add(ref word0, 4), ref sigma0Carry, ref bcXor);
				CompressDeferredRound(ref d, ref e, ref g, ref h, ref a, ref b, ref c, Unsafe.Add(ref word0, 5), ref sigma0Carry, ref bcXor);
				CompressDeferredRound(ref c, ref d, ref f, ref g, ref h, ref a, ref b, Unsafe.Add(ref word0, 6), ref sigma0Carry, ref bcXor);
				CompressDeferredRound(ref b, ref c, ref e, ref f, ref g, ref h, ref a, Unsafe.Add(ref word0, 7), ref sigma0Carry, ref bcXor);
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
			sourceRef = ref Unsafe.Add(ref sourceRef, (nuint)BlockSizeInBytes);
		} while (Unsafe.IsAddressLessThan(ref sourceRef, ref sourceEnd));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> LoadWordPairAvx2(ref byte source, nuint offset)
	{
		Vector256<byte> words = Vector256.Create(Vector128.LoadUnsafe(ref source, offset), Vector128.LoadUnsafe(ref source, BlockSizeInBytes + offset));
		return Avx2.Shuffle(words, BigEndianShuffle256).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> UpdateSchedulePairAvx2(Vector256<ulong> words0, Vector256<ulong> words1, Vector256<ulong> words4, Vector256<ulong> words5, Vector256<ulong> words7)
	{
		Vector256<ulong> sigma0Input = Avx2.AlignRight(words1, words0, 8);
		Vector256<ulong> wordsMinus7 = Avx2.AlignRight(words5, words4, 8);
		return words0 + wordsMinus7 + SmallSigma0Avx2(sigma0Input) + SmallSigma1Avx2(words7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> StoreSecondBlockRoundInputAvx2(Vector256<ulong> words, ref ulong destination, Vector128<ulong> constants, nuint round)
	{
		Vector256<ulong> roundInput = words + Vector256.Create(constants);
		roundInput.GetUpper().StoreUnsafe(ref destination, round);
		return roundInput.GetLower();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void CompressRoundInputs(ref ulong roundInput0)
	{
		ulong a = _h0;
		ulong b = _h1;
		ulong c = _h2;
		ulong d = _h3;
		ulong e = _h4;
		ulong f = _h5;
		ulong g = _h6;
		ulong h = _h7;
		ulong sigma0Carry = 0;
		ulong bcXor = b ^ c;

		for (nuint i = 0; i < 80; i += 8)
		{
			ref ulong word0 = ref Unsafe.Add(ref roundInput0, i);
			CompressDeferredRound(ref a, ref b, ref d, ref e, ref f, ref g, ref h, word0, ref sigma0Carry, ref bcXor);
			CompressDeferredRound(ref h, ref a, ref c, ref d, ref e, ref f, ref g, Unsafe.Add(ref word0, 1), ref sigma0Carry, ref bcXor);
			CompressDeferredRound(ref g, ref h, ref b, ref c, ref d, ref e, ref f, Unsafe.Add(ref word0, 2), ref sigma0Carry, ref bcXor);
			CompressDeferredRound(ref f, ref g, ref a, ref b, ref c, ref d, ref e, Unsafe.Add(ref word0, 3), ref sigma0Carry, ref bcXor);
			CompressDeferredRound(ref e, ref f, ref h, ref a, ref b, ref c, ref d, Unsafe.Add(ref word0, 4), ref sigma0Carry, ref bcXor);
			CompressDeferredRound(ref d, ref e, ref g, ref h, ref a, ref b, ref c, Unsafe.Add(ref word0, 5), ref sigma0Carry, ref bcXor);
			CompressDeferredRound(ref c, ref d, ref f, ref g, ref h, ref a, ref b, Unsafe.Add(ref word0, 6), ref sigma0Carry, ref bcXor);
			CompressDeferredRound(ref b, ref c, ref e, ref f, ref g, ref h, ref a, Unsafe.Add(ref word0, 7), ref sigma0Carry, ref bcXor);
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> LoadWordsAvx2(ref byte source, nuint offset)
	{
		Vector256<byte> words = Vector256.LoadUnsafe(ref source, offset);
		return words.ReverseEndianness64().AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRoundInputAvx2(Vector256<ulong> words, ref ulong destination, nuint destinationOffset, nuint round)
	{
		ref ulong roundConstant0 = ref RoundConstants.GetReference();
		Vector256<ulong> roundInput = words + Vector256.LoadUnsafe(ref roundConstant0, round);
		roundInput.StoreUnsafe(ref destination, destinationOffset);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> UpdateScheduleAvx2(Vector256<ulong> words0, Vector256<ulong> words1, Vector256<ulong> words2, Vector256<ulong> words3)
	{
		Vector256<ulong> sigma0Input = ShiftOneWordAvx2(words0, words1);
		Vector256<ulong> wordsMinus7 = ShiftOneWordAvx2(words2, words3);
		Vector256<ulong> result = words0 + wordsMinus7 + SmallSigma0Avx2(sigma0Input);

		Vector256<ulong> previous = Vector256.Shuffle(words3, Vector256.Create(2ul, 3, 2, 3));
		Vector256<ulong> previousSigma = SmallSigma1Avx2(previous);
		result += Avx2.Permute2x128(previousSigma, Vector256<ulong>.Zero, 0x20);

		Vector256<ulong> dependentSigma = SmallSigma1Avx2(result);
		return result + Avx2.Permute2x128(Vector256<ulong>.Zero, dependentSigma, 0x20);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> ShiftOneWordAvx2(Vector256<ulong> lower, Vector256<ulong> upper)
	{
		Vector256<ulong> middle = Avx2.Permute2x128(lower, upper, 0x21);
		return Avx2.AlignRight(middle, lower, 8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> SmallSigma0Avx2(Vector256<ulong> value)
	{
		Vector256<ulong> rotate1 = value.RotateRightUInt64(1);
		Vector256<ulong> rotate8 = value.RotateRightUInt64(8);
		return rotate1 ^ rotate8 ^ value >>> 7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> SmallSigma1Avx2(Vector256<ulong> value)
	{
		Vector256<ulong> rotate19 = value.RotateRightUInt64(19);
		Vector256<ulong> rotate61 = value.RotateRightUInt64(61);
		return rotate19 ^ rotate61 ^ value >>> 6;
	}
}
