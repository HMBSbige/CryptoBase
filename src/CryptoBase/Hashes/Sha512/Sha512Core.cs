namespace CryptoBase.Hashes.Sha512;

internal partial struct Sha512Core
{
	private UInt128 _byteCount;
	private ulong _h0;
	private ulong _h1;
	private ulong _h2;
	private ulong _h3;
	private ulong _h4;
	private ulong _h5;
	private ulong _h6;
	private ulong _h7;
	private InlineArray128<byte> _buffer;

	internal const int BlockSizeInBytes = 128;
	private const int LengthOffset = 112;

	private static ReadOnlySpan<ulong> RoundConstants =>
	[
		0x428A2F98D728AE22UL, 0x7137449123EF65CDUL, 0xB5C0FBCFEC4D3B2FUL, 0xE9B5DBA58189DBBCUL,
		0x3956C25BF348B538UL, 0x59F111F1B605D019UL, 0x923F82A4AF194F9BUL, 0xAB1C5ED5DA6D8118UL,
		0xD807AA98A3030242UL, 0x12835B0145706FBEUL, 0x243185BE4EE4B28CUL, 0x550C7DC3D5FFB4E2UL,
		0x72BE5D74F27B896FUL, 0x80DEB1FE3B1696B1UL, 0x9BDC06A725C71235UL, 0xC19BF174CF692694UL,
		0xE49B69C19EF14AD2UL, 0xEFBE4786384F25E3UL, 0x0FC19DC68B8CD5B5UL, 0x240CA1CC77AC9C65UL,
		0x2DE92C6F592B0275UL, 0x4A7484AA6EA6E483UL, 0x5CB0A9DCBD41FBD4UL, 0x76F988DA831153B5UL,
		0x983E5152EE66DFABUL, 0xA831C66D2DB43210UL, 0xB00327C898FB213FUL, 0xBF597FC7BEEF0EE4UL,
		0xC6E00BF33DA88FC2UL, 0xD5A79147930AA725UL, 0x06CA6351E003826FUL, 0x142929670A0E6E70UL,
		0x27B70A8546D22FFCUL, 0x2E1B21385C26C926UL, 0x4D2C6DFC5AC42AEDUL, 0x53380D139D95B3DFUL,
		0x650A73548BAF63DEUL, 0x766A0ABB3C77B2A8UL, 0x81C2C92E47EDAEE6UL, 0x92722C851482353BUL,
		0xA2BFE8A14CF10364UL, 0xA81A664BBC423001UL, 0xC24B8B70D0F89791UL, 0xC76C51A30654BE30UL,
		0xD192E819D6EF5218UL, 0xD69906245565A910UL, 0xF40E35855771202AUL, 0x106AA07032BBD1B8UL,
		0x19A4C116B8D2D0C8UL, 0x1E376C085141AB53UL, 0x2748774CDF8EEB99UL, 0x34B0BCB5E19B48A8UL,
		0x391C0CB3C5C95A63UL, 0x4ED8AA4AE3418ACBUL, 0x5B9CCA4F7763E373UL, 0x682E6FF3D6B2B8A3UL,
		0x748F82EE5DEFB2FCUL, 0x78A5636F43172F60UL, 0x84C87814A1F0AB72UL, 0x8CC702081A6439ECUL,
		0x90BEFFFA23631E28UL, 0xA4506CEBDE82BDE9UL, 0xBEF9A3F7B2C67915UL, 0xC67178F2E372532BUL,
		0xCA273ECEEA26619CUL, 0xD186B8C721C0C207UL, 0xEADA7DD6CDE0EB1EUL, 0xF57D4F7FEE6ED178UL,
		0x06F067AA72176FBAUL, 0x0A637DC5A2C898A6UL, 0x113F9804BEF90DAEUL, 0x1B710B35131C471BUL,
		0x28DB77F523047D84UL, 0x32CAAB7B40C72493UL, 0x3C9EBE0A15C9BEBCUL, 0x431D67C49C100D4CUL,
		0x4CC5D4BECB3E42B6UL, 0x597F299CFC657E2AUL, 0x5FCB6FAB3AD6FAECUL, 0x6C44198C4A475817UL,
	];

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Reset(ulong h0, ulong h1, ulong h2, ulong h3, ulong h4, ulong h5, ulong h6, ulong h7)
	{
		_byteCount = 0;
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
	internal void Append(ReadOnlySpan<byte> source)
	{
		int bufferedLength = (int)(_byteCount & (uint)(BlockSizeInBytes - 1));
		_byteCount += (uint)source.Length;
		int bytesNeeded = BlockSizeInBytes - bufferedLength;

		if (source.Length < bytesNeeded)
		{
			Span<byte> buffer = _buffer;
			source.CopyTo(buffer.Slice(bufferedLength));
			return;
		}

		AppendBlocks(source, bufferedLength, bytesNeeded);
	}

	[SkipLocalsInit]
	private void AppendBlocks(ReadOnlySpan<byte> source, int bufferedLength, int bytesNeeded)
	{
		Span<byte> buffer = _buffer;

		if (bufferedLength is not 0)
		{
			source.Slice(0, bytesNeeded).CopyTo(buffer.Slice(bufferedLength));
			ProcessBlocks(buffer);
			source = source.Slice(bytesNeeded);
		}

		int completeLength = source.Length & ~(BlockSizeInBytes - 1);

		if (completeLength is not 0)
		{
			ProcessBlocks(source.Slice(0, completeLength));
			source = source.Slice(completeLength);
		}

		if (!source.IsEmpty)
		{
			source.CopyTo(buffer);
		}
	}

	[SkipLocalsInit]
	internal void Finalize(Span<byte> destination, int hashLengthInBytes)
	{
		Span<byte> buffer = _buffer;
		int index = (int)(_byteCount & (uint)(BlockSizeInBytes - 1));
		buffer[index++] = 0x80;

		if (index > LengthOffset && X86Base.X64.IsSupported && Avx2.IsSupported)
		{
			FinalizeTwoBlocks(buffer, index);
		}
		else
		{
			if (index > LengthOffset)
			{
				buffer.Slice(index).Clear();
				ProcessBlocks(buffer);
				index = 0;
			}

			buffer.Slice(index, LengthOffset - index).Clear();
			BinaryPrimitives.WriteUInt128BigEndian(buffer.Slice(LengthOffset), _byteCount << 3);
			ProcessBlocks(buffer);
		}

		BinaryPrimitives.WriteUInt64BigEndian(destination, _h0);
		BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(8), _h1);
		BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(16), _h2);
		BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(24), _h3);
		BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(32), _h4);
		BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(40), _h5);

		if (hashLengthInBytes is Sha512HashAlgorithm.HashSizeInBytes)
		{
			BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(48), _h6);
			BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(56), _h7);
		}
	}

	[SkipLocalsInit]
	private void FinalizeTwoBlocks(ReadOnlySpan<byte> buffer, int index)
	{
		Debug.Assert(X86Base.X64.IsSupported);
		Debug.Assert(Avx2.IsSupported);
		Debug.Assert(index > LengthOffset);

		using CryptoBuffer<byte> finalBlocks = new(stackalloc byte[2 * BlockSizeInBytes]);
		int finalLengthOffset = finalBlocks.Span.Length - 2 * sizeof(ulong);
		buffer.Slice(0, index).CopyTo(finalBlocks.Span);
		finalBlocks.Span.Slice(index, finalLengthOffset - index).Clear();
		BinaryPrimitives.WriteUInt128BigEndian(finalBlocks.Span.Slice(finalLengthOffset), _byteCount << 3);
		ProcessBlockPairsAvx2(finalBlocks.Span);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlocks(ReadOnlySpan<byte> source)
	{
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		if (Avx2.IsSupported)
		{
			ProcessBlocksAvx2(source);
			return;
		}

		ProcessBlocksSoftware(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressTwoRounds(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ref ulong e, ref ulong f, ref ulong g, ref ulong h, Vector128<ulong> roundInput, ref ulong sigma0Carry, ref ulong bcXor)
	{
		CompressDeferredRound(ref a, ref b, ref d, ref e, ref f, ref g, ref h, roundInput.ToScalar(), ref sigma0Carry, ref bcXor);
		CompressDeferredRound(ref h, ref a, ref c, ref d, ref e, ref f, ref g, roundInput.GetElement(1), ref sigma0Carry, ref bcXor);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressDeferredRound(ref ulong a, ref ulong b, ref ulong d, ref ulong e, ref ulong f, ref ulong g, ref ulong h, ulong roundInput, ref ulong sigma0Carry, ref ulong bcXor)
	{
		a += sigma0Carry;
		h += roundInput;
		h += Choose(e, f, g);
		h += BigSigma1(e);
		d += h;
		ulong nextBcXor = a ^ b;
		h += bcXor & nextBcXor ^ b;
		sigma0Carry = BigSigma0(a);
		bcXor = nextBcXor;
	}

	[SkipLocalsInit]
	private void ProcessBlocksSoftware(ReadOnlySpan<byte> source)
	{
		Unsafe.SkipInit(out InlineArray16<ulong> schedule);
		ref ulong schedule0 = ref schedule[0];
		ref byte block0 = ref source.GetReference();
		int remainingLength = source.Length;

		do
		{
			LoadFourSoftwareWords(out schedule0, ref block0);
			LoadFourSoftwareWords(out Unsafe.Add(ref schedule0, 4), ref Unsafe.Add(ref block0, 32));
			LoadFourSoftwareWords(out Unsafe.Add(ref schedule0, 8), ref Unsafe.Add(ref block0, 64));
			LoadFourSoftwareWords(out Unsafe.Add(ref schedule0, 12), ref Unsafe.Add(ref block0, 96));

			ulong a = _h0;
			ulong b = _h1;
			ulong c = _h2;
			ulong d = _h3;
			ulong e = _h4;
			ulong f = _h5;
			ulong g = _h6;
			ulong h = _h7;
			ref ulong roundConstant0 = ref RoundConstants.GetReference();

			CompressLoadedEightSoftwareRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref roundConstant0, 0);
			CompressLoadedEightSoftwareRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref roundConstant0, 8);

			for (int round = 16; round < 80; round += 16)
			{
				ref ulong currentRoundConstant = ref Unsafe.Add(ref roundConstant0, round);
				ExpandAndCompressEightSoftwareRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref currentRoundConstant, 0);
				ExpandAndCompressEightSoftwareRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref currentRoundConstant, 8);
			}

			_h0 += a;
			_h1 += b;
			_h2 += c;
			_h3 += d;
			_h4 += e;
			_h5 += f;
			_h6 += g;
			_h7 += h;
			block0 = ref Unsafe.Add(ref block0, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadFourSoftwareWords(out ulong destination, ref byte source)
	{
		destination = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref source));
		Unsafe.Add(ref destination, 1) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 8)));
		Unsafe.Add(ref destination, 2) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 16)));
		Unsafe.Add(ref destination, 3) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 24)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressLoadedEightSoftwareRounds(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ref ulong e, ref ulong f, ref ulong g, ref ulong h, ref ulong schedule, ref ulong roundConstants, int round)
	{
		CompressSoftwareRound(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, LoadedRoundInput(ref schedule, ref roundConstants, round));
		CompressSoftwareRound(ref h, ref a, ref b, ref c, ref d, ref e, ref f, ref g, LoadedRoundInput(ref schedule, ref roundConstants, round + 1));
		CompressSoftwareRound(ref g, ref h, ref a, ref b, ref c, ref d, ref e, ref f, LoadedRoundInput(ref schedule, ref roundConstants, round + 2));
		CompressSoftwareRound(ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref e, LoadedRoundInput(ref schedule, ref roundConstants, round + 3));
		CompressSoftwareRound(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, LoadedRoundInput(ref schedule, ref roundConstants, round + 4));
		CompressSoftwareRound(ref d, ref e, ref f, ref g, ref h, ref a, ref b, ref c, LoadedRoundInput(ref schedule, ref roundConstants, round + 5));
		CompressSoftwareRound(ref c, ref d, ref e, ref f, ref g, ref h, ref a, ref b, LoadedRoundInput(ref schedule, ref roundConstants, round + 6));
		CompressSoftwareRound(ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref a, LoadedRoundInput(ref schedule, ref roundConstants, round + 7));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandAndCompressEightSoftwareRounds(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ref ulong e, ref ulong f, ref ulong g, ref ulong h, ref ulong schedule, ref ulong roundConstants, int round)
	{
		CompressSoftwareRound(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ExpandedRoundInput(ref schedule, ref roundConstants, round));
		CompressSoftwareRound(ref h, ref a, ref b, ref c, ref d, ref e, ref f, ref g, ExpandedRoundInput(ref schedule, ref roundConstants, round + 1));
		CompressSoftwareRound(ref g, ref h, ref a, ref b, ref c, ref d, ref e, ref f, ExpandedRoundInput(ref schedule, ref roundConstants, round + 2));
		CompressSoftwareRound(ref f, ref g, ref h, ref a, ref b, ref c, ref d, ref e, ExpandedRoundInput(ref schedule, ref roundConstants, round + 3));
		CompressSoftwareRound(ref e, ref f, ref g, ref h, ref a, ref b, ref c, ref d, ExpandedRoundInput(ref schedule, ref roundConstants, round + 4));
		CompressSoftwareRound(ref d, ref e, ref f, ref g, ref h, ref a, ref b, ref c, ExpandedRoundInput(ref schedule, ref roundConstants, round + 5));
		CompressSoftwareRound(ref c, ref d, ref e, ref f, ref g, ref h, ref a, ref b, ExpandedRoundInput(ref schedule, ref roundConstants, round + 6));
		CompressSoftwareRound(ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref a, ExpandedRoundInput(ref schedule, ref roundConstants, round + 7));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressSoftwareRound(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ref ulong e, ref ulong f, ref ulong g, ref ulong h, ulong roundInput)
	{
		h = h + roundInput + Choose(e, f, g) + BigSigma1Software(e);
		d += h;
		h = h + Majority(a, b, c) + BigSigma0Software(a);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong LoadedRoundInput(ref ulong schedule, ref ulong roundConstants, int round)
	{
		return Unsafe.Add(ref schedule, round) + Unsafe.Add(ref roundConstants, round);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ExpandedRoundInput(ref ulong schedule, ref ulong roundConstants, int round)
	{
		int index = round & 15;
		ulong word = Unsafe.Add(ref schedule, index)
					+ SmallSigma0Software(Unsafe.Add(ref schedule, index + 1 & 15))
					+ Unsafe.Add(ref schedule, index + 9 & 15)
					+ SmallSigma1Software(Unsafe.Add(ref schedule, index + 14 & 15));
		Unsafe.Add(ref schedule, index) = word;
		return word + Unsafe.Add(ref roundConstants, round);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Choose(ulong x, ulong y, ulong z)
	{
		return (y ^ z) & x ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Majority(ulong x, ulong y, ulong z)
	{
		return x & y | (x | y) & z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong BigSigma0(ulong x)
	{
		return x.RotateRight(28) ^ x.RotateRight(34) ^ x.RotateRight(39);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong BigSigma0Software(ulong x)
	{
		ulong result = x.RotateRight(5) ^ x;
		result = result.RotateRight(6) ^ x;
		return result.RotateRight(28);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong BigSigma1(ulong x)
	{
		return x.RotateRight(14) ^ x.RotateRight(18) ^ x.RotateRight(41);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong BigSigma1Software(ulong x)
	{
		ulong result = x.RotateRight(23) ^ x;
		result = result.RotateRight(4) ^ x;
		return result.RotateRight(14);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong SmallSigma0Software(ulong x)
	{
		ulong result = x.RotateRight(7) ^ x;
		return result.RotateRight(1) ^ x >> 7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong SmallSigma1Software(ulong x)
	{
		ulong result = x.RotateRight(42) ^ x;
		return result.RotateRight(19) ^ x >> 6;
	}
}
