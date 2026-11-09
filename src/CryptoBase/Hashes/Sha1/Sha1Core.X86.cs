namespace CryptoBase.Hashes.Sha1;

public partial struct Sha1Core
{
	[SkipLocalsInit]
	private void ProcessBlocksSsse3(ReadOnlySpan<byte> source)
	{
		Debug.Assert(X86Base.X64.IsSupported && Ssse3.IsSupported);

		ref byte blockRef = ref MemoryMarshal.GetReference(source);
		int remainingLength = source.Length;
		uint a = _h0;
		uint b = _h1;
		uint c = _h2;
		uint d = _h3;
		uint e = _h4;
		Unsafe.SkipInit(out InlineArray16<uint> roundInputs);

		do
		{
			uint savedA = a;
			uint savedB = b;
			uint savedC = c;
			uint savedD = d;
			uint savedE = e;
			Vector128<uint> words0 = HashCoreUtils.LoadBigEndianWords(ref blockRef, 0);
			Vector128<uint> words1 = HashCoreUtils.LoadBigEndianWords(ref blockRef, 16);
			Vector128<uint> words2 = HashCoreUtils.LoadBigEndianWords(ref blockRef, 32);
			Vector128<uint> words3 = HashCoreUtils.LoadBigEndianWords(ref blockRef, 48);
			StoreRoundInputsX86(words0, ChooseConstant, ref roundInputs[0]);
			StoreRoundInputsX86(words1, ChooseConstant, ref roundInputs[4]);
			StoreRoundInputsX86(words2, ChooseConstant, ref roundInputs[8]);
			StoreRoundInputsX86(words3, ChooseConstant, ref roundInputs[12]);

			RoundsX86<Choose>(ref a, ref b, ref c, ref d, ref e, ref roundInputs[0]);
			Vector128<uint> words4 = UpdateX86Schedule(words0, words1, words2, words3);
			StoreRoundInputsX86(words4, ChooseConstant, ref roundInputs[0]);
			RoundsX86<Choose>(ref b, ref c, ref d, ref e, ref a, ref roundInputs[4]);
			Vector128<uint> words5 = UpdateX86Schedule(words1, words2, words3, words4);
			StoreRoundInputsX86(words5, ParityConstant1, ref roundInputs[4]);
			RoundsX86<Choose>(ref c, ref d, ref e, ref a, ref b, ref roundInputs[8]);
			Vector128<uint> words6 = UpdateX86Schedule(words2, words3, words4, words5);
			StoreRoundInputsX86(words6, ParityConstant1, ref roundInputs[8]);
			RoundsX86<Choose>(ref d, ref e, ref a, ref b, ref c, ref roundInputs[12]);
			Vector128<uint> words7 = UpdateX86Schedule(words3, words4, words5, words6);
			StoreRoundInputsX86(words7, ParityConstant1, ref roundInputs[12]);
			RoundsX86<Choose>(ref e, ref a, ref b, ref c, ref d, ref roundInputs[0]);
			words0 = UpdateX86Schedule32(words0, words1, words4, words6, words7);
			StoreRoundInputsX86(words0, ParityConstant1, ref roundInputs[0]);

			RoundsX86<Parity>(ref a, ref b, ref c, ref d, ref e, ref roundInputs[4]);
			words1 = UpdateX86Schedule32(words1, words2, words5, words7, words0);
			StoreRoundInputsX86(words1, ParityConstant1, ref roundInputs[4]);
			RoundsX86<Parity>(ref b, ref c, ref d, ref e, ref a, ref roundInputs[8]);
			words2 = UpdateX86Schedule32(words2, words3, words6, words0, words1);
			StoreRoundInputsX86(words2, MajorityConstant, ref roundInputs[8]);
			RoundsX86<Parity>(ref c, ref d, ref e, ref a, ref b, ref roundInputs[12]);
			words3 = UpdateX86Schedule32(words3, words4, words7, words1, words2);
			StoreRoundInputsX86(words3, MajorityConstant, ref roundInputs[12]);
			RoundsX86<Parity>(ref d, ref e, ref a, ref b, ref c, ref roundInputs[0]);
			words4 = UpdateX86Schedule32(words4, words5, words0, words2, words3);
			StoreRoundInputsX86(words4, MajorityConstant, ref roundInputs[0]);
			RoundsX86<Parity>(ref e, ref a, ref b, ref c, ref d, ref roundInputs[4]);
			words5 = UpdateX86Schedule32(words5, words6, words1, words3, words4);
			StoreRoundInputsX86(words5, MajorityConstant, ref roundInputs[4]);

			RoundsX86<Majority>(ref a, ref b, ref c, ref d, ref e, ref roundInputs[8]);
			words6 = UpdateX86Schedule32(words6, words7, words2, words4, words5);
			StoreRoundInputsX86(words6, MajorityConstant, ref roundInputs[8]);
			RoundsX86<Majority>(ref b, ref c, ref d, ref e, ref a, ref roundInputs[12]);
			words7 = UpdateX86Schedule32(words7, words0, words3, words5, words6);
			StoreRoundInputsX86(words7, ParityConstant2, ref roundInputs[12]);
			RoundsX86<Majority>(ref c, ref d, ref e, ref a, ref b, ref roundInputs[0]);
			words0 = UpdateX86Schedule32(words0, words1, words4, words6, words7);
			StoreRoundInputsX86(words0, ParityConstant2, ref roundInputs[0]);
			RoundsX86<Majority>(ref d, ref e, ref a, ref b, ref c, ref roundInputs[4]);
			words1 = UpdateX86Schedule32(words1, words2, words5, words7, words0);
			StoreRoundInputsX86(words1, ParityConstant2, ref roundInputs[4]);
			RoundsX86<Majority>(ref e, ref a, ref b, ref c, ref d, ref roundInputs[8]);
			words2 = UpdateX86Schedule32(words2, words3, words6, words0, words1);
			StoreRoundInputsX86(words2, ParityConstant2, ref roundInputs[8]);

			RoundsX86<Parity>(ref a, ref b, ref c, ref d, ref e, ref roundInputs[12]);
			words3 = UpdateX86Schedule32(words3, words4, words7, words1, words2);
			StoreRoundInputsX86(words3, ParityConstant2, ref roundInputs[12]);
			RoundsX86<Parity>(ref b, ref c, ref d, ref e, ref a, ref roundInputs[0]);
			RoundsX86<Parity>(ref c, ref d, ref e, ref a, ref b, ref roundInputs[4]);
			RoundsX86<Parity>(ref d, ref e, ref a, ref b, ref c, ref roundInputs[8]);
			RoundsX86<Parity>(ref e, ref a, ref b, ref c, ref d, ref roundInputs[12]);

			a += savedA;
			b += savedB;
			c += savedC;
			d += savedD;
			e += savedE;
			blockRef = ref Unsafe.Add(ref blockRef, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);

		_h0 = a;
		_h1 = b;
		_h2 = c;
		_h3 = d;
		_h4 = e;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> UpdateX86Schedule(Vector128<uint> words0, Vector128<uint> words1, Vector128<uint> words2, Vector128<uint> words3)
	{
		Vector128<uint> words2To5 = Ssse3.AlignRight(words1, words0, 8);
		Vector128<uint> words13To15 = Sse2.ShiftRightLogical128BitLane(words3, 4);
		Vector128<uint> next = (words0 ^ words2 ^ words2To5 ^ words13To15).RotateLeftUInt32(1);
		Vector128<uint> carry = Sse2.ShiftLeftLogical128BitLane(next.RotateLeftUInt32(1), 12);
		return next ^ carry;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> UpdateX86Schedule32(Vector128<uint> wordsMinus32, Vector128<uint> wordsMinus28, Vector128<uint> wordsMinus16, Vector128<uint> wordsMinus8, Vector128<uint> wordsMinus4)
	{
		// W[t] = ROTL2(W[t-32] ^ W[t-28] ^ W[t-16] ^ W[t-6]), t >= 32.
		Vector128<uint> wordsMinus6ToMinus3 = Ssse3.AlignRight(wordsMinus4, wordsMinus8, 8);
		return (wordsMinus32 ^ wordsMinus28 ^ wordsMinus16 ^ wordsMinus6ToMinus3).RotateLeftUInt32(2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRoundInputsX86(Vector128<uint> words, uint roundConstant, ref uint destination)
	{
		(words + Vector128.Create(roundConstant)).StoreUnsafe(ref destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void RoundsX86<TFunction>(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint roundInput0) where TFunction : IRoundFunction
	{
		Round<TFunction>(ref a, ref b, ref c, ref d, ref e, roundInput0);
		Round<TFunction>(ref e, ref a, ref b, ref c, ref d, Unsafe.Add(ref roundInput0, 1));
		Round<TFunction>(ref d, ref e, ref a, ref b, ref c, Unsafe.Add(ref roundInput0, 2));
		Round<TFunction>(ref c, ref d, ref e, ref a, ref b, Unsafe.Add(ref roundInput0, 3));
	}
}
