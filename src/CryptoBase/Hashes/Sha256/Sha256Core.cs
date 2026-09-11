using Sha256Arm = System.Runtime.Intrinsics.Arm.Sha256;

namespace CryptoBase.Hashes.Sha256;

internal partial struct Sha256Core
{
	private ulong _byteCount;
	private uint _h0;
	private uint _h1;
	private uint _h2;
	private uint _h3;
	private uint _h4;
	private uint _h5;
	private uint _h6;
	private uint _h7;
	private InlineArray64<byte> _buffer;

	internal const int BlockSizeInBytes = 64;
	private const int LengthOffset = 56;

	private static ReadOnlySpan<uint> RoundConstants =>
	[
		0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
		0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
		0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
		0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U, 0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
		0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
		0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
		0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
		0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U,
	];

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Reset(uint h0, uint h1, uint h2, uint h3, uint h4, uint h5, uint h6, uint h7)
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
		int bufferedLength = (int)(_byteCount & BlockSizeInBytes - 1);
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

	internal void Finalize(Span<byte> destination, int hashLengthInBytes)
	{
		Span<byte> buffer = _buffer;
		int index = (int)(_byteCount & BlockSizeInBytes - 1);
		buffer[index++] = 0x80;

		if (index > LengthOffset && Avx2.IsSupported)
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
			BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(LengthOffset), _byteCount << 3);
			ProcessBlocks(buffer);
		}

		BinaryPrimitives.WriteUInt32BigEndian(destination, _h0);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), _h1);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), _h2);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), _h3);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(16), _h4);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(20), _h5);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(24), _h6);

		if (hashLengthInBytes is Sha256HashAlgorithm.HashSizeInBytes)
		{
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(28), _h7);
		}
	}

	[SkipLocalsInit]
	private void FinalizeTwoBlocks(ReadOnlySpan<byte> buffer, int index)
	{
		Debug.Assert(Avx2.IsSupported);
		Debug.Assert(index > LengthOffset);
		using CryptoBuffer<byte> finalBlocks = new(stackalloc byte[2 * BlockSizeInBytes]);
		buffer.Slice(0, index).CopyTo(finalBlocks.Span);
		finalBlocks.Span.Slice(index, 2 * BlockSizeInBytes - sizeof(ulong) - index).Clear();
		BinaryPrimitives.WriteUInt64BigEndian(finalBlocks.Span.Slice(2 * BlockSizeInBytes - sizeof(ulong)), _byteCount << 3);
		ProcessBlocksAvx2(finalBlocks.Span);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlocks(ReadOnlySpan<byte> source)
	{
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		if (Sha256Arm.Arm64.IsSupported)
		{
			ProcessBlocksArm64(source);
			return;
		}

		if (AdvSimd.Arm64.IsSupported)
		{
			ProcessBlocksAdvSimd(source);
			return;
		}

		if
		(
			Avx2.IsSupported
			&& source.Length >= 2 * BlockSizeInBytes
			&& (X86Base.X64.IsSupported || (source.Length / BlockSizeInBytes & 1) is 0 || source.Length >= 7 * BlockSizeInBytes)
		)
		{
			ProcessBlocksAvx2(source);
			return;
		}

		ProcessBlocksSoftware(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressFourRounds(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h, ref uint roundInput0, ref uint sigma0Carry, ref uint bcXor)
	{
		CompressDeferredRound(ref a, ref b, ref d, ref e, ref f, ref g, ref h, roundInput0, ref sigma0Carry, ref bcXor);
		CompressDeferredRound(ref h, ref a, ref c, ref d, ref e, ref f, ref g, Unsafe.Add(ref roundInput0, 1), ref sigma0Carry, ref bcXor);
		CompressDeferredRound(ref g, ref h, ref b, ref c, ref d, ref e, ref f, Unsafe.Add(ref roundInput0, 2), ref sigma0Carry, ref bcXor);
		CompressDeferredRound(ref f, ref g, ref a, ref b, ref c, ref d, ref e, Unsafe.Add(ref roundInput0, 3), ref sigma0Carry, ref bcXor);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressDeferredRound(ref uint a, ref uint b, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h, uint roundInput, ref uint sigma0Carry, ref uint bcXor)
	{
		a += sigma0Carry;
		h += roundInput;
		h += Choose(e, f, g);
		h += BigSigma1(e);
		d += h;
		uint nextBcXor = a ^ b;
		h += bcXor & nextBcXor ^ b;
		sigma0Carry = BigSigma0(a);
		bcXor = nextBcXor;
	}

	[SkipLocalsInit]
	private void ProcessBlocksSoftware(ReadOnlySpan<byte> source)
	{
		Unsafe.SkipInit(out InlineArray16<uint> schedule);
		ref uint schedule0 = ref schedule[0];
		ref byte block0 = ref source.GetReference();
		int remainingLength = source.Length;

		do
		{
			HashCoreUtils.LoadFourBigEndianWords(out schedule0, ref block0);
			HashCoreUtils.LoadFourBigEndianWords(out Unsafe.Add(ref schedule0, 4), ref Unsafe.Add(ref block0, 16));
			HashCoreUtils.LoadFourBigEndianWords(out Unsafe.Add(ref schedule0, 8), ref Unsafe.Add(ref block0, 32));
			HashCoreUtils.LoadFourBigEndianWords(out Unsafe.Add(ref schedule0, 12), ref Unsafe.Add(ref block0, 48));

			uint a = _h0;
			uint b = _h1;
			uint c = _h2;
			uint d = _h3;
			uint e = _h4;
			uint f = _h5;
			uint g = _h6;
			uint h = _h7;
			ref uint roundConstant0 = ref RoundConstants.GetReference();

			CompressLoadedEightSoftwareRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref roundConstant0, 0);
			CompressLoadedEightSoftwareRounds(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref schedule0, ref roundConstant0, 8);

			for (int round = 16; round < 64; round += 16)
			{
				ref uint currentRoundConstant = ref Unsafe.Add(ref roundConstant0, round);
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
	private static void CompressLoadedEightSoftwareRounds(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h, ref uint schedule, ref uint roundConstants, int round)
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
	private static void ExpandAndCompressEightSoftwareRounds(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h, ref uint schedule, ref uint roundConstants, int round)
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
	private static void CompressSoftwareRound(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h, uint roundInput)
	{
		h = h + roundInput + Choose(e, f, g) + BigSigma1Software(e);
		d += h;
		h = h + Majority(a, b, c) + BigSigma0Software(a);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint LoadedRoundInput(ref uint schedule, ref uint roundConstants, int round)
	{
		return Unsafe.Add(ref schedule, round) + Unsafe.Add(ref roundConstants, round);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint ExpandedRoundInput(ref uint schedule, ref uint roundConstants, int round)
	{
		int index = round & 15;
		uint word =
			Unsafe.Add(ref schedule, index)
			+ SmallSigma0Software(Unsafe.Add(ref schedule, index + 1 & 15))
			+ Unsafe.Add(ref schedule, index + 9 & 15)
			+ SmallSigma1Software(Unsafe.Add(ref schedule, index + 14 & 15));
		Unsafe.Add(ref schedule, index) = word;
		return word + Unsafe.Add(ref roundConstants, round);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Choose(uint x, uint y, uint z)
	{
		return (y ^ z) & x ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Majority(uint x, uint y, uint z)
	{
		return x & y | (x | y) & z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint BigSigma0(uint value)
	{
		return value.RotateRight(2) ^ value.RotateRight(13) ^ value.RotateRight(22);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint BigSigma0Software(uint value)
	{
		uint result = value.RotateRight(9) ^ value;
		result = result.RotateRight(11) ^ value;
		return result.RotateRight(2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint BigSigma1(uint value)
	{
		return value.RotateRight(6) ^ value.RotateRight(11) ^ value.RotateRight(25);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint BigSigma1Software(uint value)
	{
		uint result = value.RotateRight(14) ^ value;
		result = result.RotateRight(5) ^ value;
		return result.RotateRight(6);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint SmallSigma0Software(uint value)
	{
		uint result = value.RotateRight(11) ^ value;
		return result.RotateRight(7) ^ value >> 3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint SmallSigma1Software(uint value)
	{
		uint result = value.RotateRight(2) ^ value;
		return result.RotateRight(17) ^ value >> 10;
	}
}
