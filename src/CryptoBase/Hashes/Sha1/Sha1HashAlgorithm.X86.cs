namespace CryptoBase.Hashes.Sha1;

public partial struct Sha1HashAlgorithm
{
	[SkipLocalsInit]
	private static void ProcessBlocksSsse3(ref Sha1HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source)
	{
		Debug.Assert(X86Base.X64.IsSupported && Ssse3.IsSupported);

		ref byte blockRef = ref source.GetReference();
		int remainingLength = source.Length;
		uint a = hashAlgorithm._h0;
		uint b = hashAlgorithm._h1;
		uint c = hashAlgorithm._h2;
		uint d = hashAlgorithm._h3;
		uint e = hashAlgorithm._h4;
		Unsafe.SkipInit(out InlineArray16<uint> roundInputs);

		do
		{
			uint savedA = a;
			uint savedB = b;
			uint savedC = c;
			uint savedD = d;
			uint savedE = e;
			Vector128<uint> words0 = LoadX86Words(ref blockRef);
			Vector128<uint> words1 = LoadX86Words(ref Unsafe.Add(ref blockRef, 16));
			Vector128<uint> words2 = LoadX86Words(ref Unsafe.Add(ref blockRef, 32));
			Vector128<uint> words3 = LoadX86Words(ref Unsafe.Add(ref blockRef, 48));
			StoreRoundInputsX86(words0, ChooseConstant, ref roundInputs[0]);
			StoreRoundInputsX86(words1, ChooseConstant, ref roundInputs[4]);
			StoreRoundInputsX86(words2, ChooseConstant, ref roundInputs[8]);
			StoreRoundInputsX86(words3, ChooseConstant, ref roundInputs[12]);

			ChooseRoundsX86(ref a, ref b, ref c, ref d, ref e, ref roundInputs[0]);
			Vector128<uint> words4 = UpdateX86Schedule(words0, words1, words2, words3);
			StoreRoundInputsX86(words4, ChooseConstant, ref roundInputs[0]);
			ChooseRoundsX86(ref b, ref c, ref d, ref e, ref a, ref roundInputs[4]);
			Vector128<uint> words5 = UpdateX86Schedule(words1, words2, words3, words4);
			StoreRoundInputsX86(words5, ParityConstant1, ref roundInputs[4]);
			ChooseRoundsX86(ref c, ref d, ref e, ref a, ref b, ref roundInputs[8]);
			Vector128<uint> words6 = UpdateX86Schedule(words2, words3, words4, words5);
			StoreRoundInputsX86(words6, ParityConstant1, ref roundInputs[8]);
			ChooseRoundsX86(ref d, ref e, ref a, ref b, ref c, ref roundInputs[12]);
			Vector128<uint> words7 = UpdateX86Schedule(words3, words4, words5, words6);
			StoreRoundInputsX86(words7, ParityConstant1, ref roundInputs[12]);
			ChooseRoundsX86(ref e, ref a, ref b, ref c, ref d, ref roundInputs[0]);
			words0 = UpdateX86Schedule32(words0, words1, words4, words6, words7);
			StoreRoundInputsX86(words0, ParityConstant1, ref roundInputs[0]);

			ParityRoundsX86(ref a, ref b, ref c, ref d, ref e, ref roundInputs[4]);
			words1 = UpdateX86Schedule32(words1, words2, words5, words7, words0);
			StoreRoundInputsX86(words1, ParityConstant1, ref roundInputs[4]);
			ParityRoundsX86(ref b, ref c, ref d, ref e, ref a, ref roundInputs[8]);
			words2 = UpdateX86Schedule32(words2, words3, words6, words0, words1);
			StoreRoundInputsX86(words2, MajorityConstant, ref roundInputs[8]);
			ParityRoundsX86(ref c, ref d, ref e, ref a, ref b, ref roundInputs[12]);
			words3 = UpdateX86Schedule32(words3, words4, words7, words1, words2);
			StoreRoundInputsX86(words3, MajorityConstant, ref roundInputs[12]);
			ParityRoundsX86(ref d, ref e, ref a, ref b, ref c, ref roundInputs[0]);
			words4 = UpdateX86Schedule32(words4, words5, words0, words2, words3);
			StoreRoundInputsX86(words4, MajorityConstant, ref roundInputs[0]);
			ParityRoundsX86(ref e, ref a, ref b, ref c, ref d, ref roundInputs[4]);
			words5 = UpdateX86Schedule32(words5, words6, words1, words3, words4);
			StoreRoundInputsX86(words5, MajorityConstant, ref roundInputs[4]);

			MajorityRoundsX86(ref a, ref b, ref c, ref d, ref e, ref roundInputs[8]);
			words6 = UpdateX86Schedule32(words6, words7, words2, words4, words5);
			StoreRoundInputsX86(words6, MajorityConstant, ref roundInputs[8]);
			MajorityRoundsX86(ref b, ref c, ref d, ref e, ref a, ref roundInputs[12]);
			words7 = UpdateX86Schedule32(words7, words0, words3, words5, words6);
			StoreRoundInputsX86(words7, ParityConstant2, ref roundInputs[12]);
			MajorityRoundsX86(ref c, ref d, ref e, ref a, ref b, ref roundInputs[0]);
			words0 = UpdateX86Schedule32(words0, words1, words4, words6, words7);
			StoreRoundInputsX86(words0, ParityConstant2, ref roundInputs[0]);
			MajorityRoundsX86(ref d, ref e, ref a, ref b, ref c, ref roundInputs[4]);
			words1 = UpdateX86Schedule32(words1, words2, words5, words7, words0);
			StoreRoundInputsX86(words1, ParityConstant2, ref roundInputs[4]);
			MajorityRoundsX86(ref e, ref a, ref b, ref c, ref d, ref roundInputs[8]);
			words2 = UpdateX86Schedule32(words2, words3, words6, words0, words1);
			StoreRoundInputsX86(words2, ParityConstant2, ref roundInputs[8]);

			ParityRoundsX86(ref a, ref b, ref c, ref d, ref e, ref roundInputs[12]);
			words3 = UpdateX86Schedule32(words3, words4, words7, words1, words2);
			StoreRoundInputsX86(words3, ParityConstant2, ref roundInputs[12]);
			ParityRoundsX86(ref b, ref c, ref d, ref e, ref a, ref roundInputs[0]);
			ParityRoundsX86(ref c, ref d, ref e, ref a, ref b, ref roundInputs[4]);
			ParityRoundsX86(ref d, ref e, ref a, ref b, ref c, ref roundInputs[8]);
			ParityRoundsX86(ref e, ref a, ref b, ref c, ref d, ref roundInputs[12]);

			a += savedA;
			b += savedB;
			c += savedC;
			d += savedD;
			e += savedE;
			blockRef = ref Unsafe.Add(ref blockRef, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);

		hashAlgorithm._h0 = a;
		hashAlgorithm._h1 = b;
		hashAlgorithm._h2 = c;
		hashAlgorithm._h3 = d;
		hashAlgorithm._h4 = e;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> LoadX86Words(ref byte source)
	{
		Vector128<byte> words = Vector128.LoadUnsafe(ref source);
		return words.ReverseEndianness32().AsUInt32();
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
	private static void ChooseRoundsX86(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint roundInput0)
	{
		ChooseRoundInput(ref a, ref b, ref c, ref d, ref e, roundInput0);
		ChooseRoundInput(ref e, ref a, ref b, ref c, ref d, Unsafe.Add(ref roundInput0, 1));
		ChooseRoundInput(ref d, ref e, ref a, ref b, ref c, Unsafe.Add(ref roundInput0, 2));
		ChooseRoundInput(ref c, ref d, ref e, ref a, ref b, Unsafe.Add(ref roundInput0, 3));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ParityRoundsX86(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint roundInput0)
	{
		ParityRoundInput(ref a, ref b, ref c, ref d, ref e, roundInput0);
		ParityRoundInput(ref e, ref a, ref b, ref c, ref d, Unsafe.Add(ref roundInput0, 1));
		ParityRoundInput(ref d, ref e, ref a, ref b, ref c, Unsafe.Add(ref roundInput0, 2));
		ParityRoundInput(ref c, ref d, ref e, ref a, ref b, Unsafe.Add(ref roundInput0, 3));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MajorityRoundsX86(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint roundInput0)
	{
		MajorityRoundInput(ref a, ref b, ref c, ref d, ref e, roundInput0);
		MajorityRoundInput(ref e, ref a, ref b, ref c, ref d, Unsafe.Add(ref roundInput0, 1));
		MajorityRoundInput(ref d, ref e, ref a, ref b, ref c, Unsafe.Add(ref roundInput0, 2));
		MajorityRoundInput(ref c, ref d, ref e, ref a, ref b, Unsafe.Add(ref roundInput0, 3));
	}
}
