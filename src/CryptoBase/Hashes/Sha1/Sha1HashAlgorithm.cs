using Sha1Arm = System.Runtime.Intrinsics.Arm.Sha1;

namespace CryptoBase.Hashes.Sha1;

/// <summary>
/// Provides the SHA-1 hash core.
/// </summary>
public partial struct Sha1HashAlgorithm : IHmacHashCore<Sha1HashAlgorithm>
{
	private const int LengthOffset = 56;
	private const int HashSizeInBytes = 20;
	private const uint ChooseConstant = 0x5A827999U;
	private const uint ParityConstant1 = 0x6ED9EBA1U;
	private const uint MajorityConstant = 0x8F1BBCDCU;
	private const uint ParityConstant2 = 0xCA62C1D6U;

	private ulong _byteCount;
	private uint _h0;
	private uint _h1;
	private uint _h2;
	private uint _h3;
	private uint _h4;
	private InlineArray64<byte> _buffer;

	private const int BlockSizeInBytes = 64;

	/// <inheritdoc />
	public static int HashLengthInBytes => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSizeInBytes => BlockSizeInBytes;

	[SkipLocalsInit]
	static Sha1HashAlgorithm IHashCore<Sha1HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out Sha1HashAlgorithm hashAlgorithm);
		hashAlgorithm.Reset();
		return hashAlgorithm;
	}

	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		int bufferedLength = (int)(_byteCount & BlockSizeInBytes - 1);
		_byteCount += (uint)source.Length;
		Span<byte> buffer = _buffer;
		int bytesNeeded = BlockSizeInBytes - bufferedLength;

		if (source.Length < bytesNeeded)
		{
			source.CopyTo(buffer.Slice(bufferedLength));
			return;
		}

		if (bufferedLength is not 0)
		{
			source.Slice(0, bytesNeeded).CopyTo(buffer.Slice(bufferedLength));
			ProcessBlocks(ref this, buffer);
			source = source.Slice(bytesNeeded);
		}

		int completeLength = source.Length & ~(BlockSizeInBytes - 1);

		if (completeLength is not 0)
		{
			ProcessBlocks(ref this, source.Slice(0, completeLength));
			source = source.Slice(completeLength);
		}

		if (!source.IsEmpty)
		{
			source.CopyTo(buffer);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Reset()
	{
		_byteCount = 0;
		_h0 = 0x67452301U;
		_h1 = 0xEFCDAB89U;
		_h2 = 0x98BADCFEU;
		_h3 = 0x10325476U;
		_h4 = 0xC3D2E1F0U;
	}

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLengthInBytes, nameof(destination));
		Finalize(ref this, destination);
	}

	private static void Finalize(ref Sha1HashAlgorithm hashAlgorithm, Span<byte> destination)
	{
		Span<byte> buffer = hashAlgorithm._buffer;
		int index = (int)(hashAlgorithm._byteCount & BlockSizeInBytes - 1);
		buffer[index++] = 0x80;

		if (index > LengthOffset)
		{
			buffer.Slice(index).Clear();
			ProcessBlocks(ref hashAlgorithm, buffer);
			index = 0;
		}

		buffer.Slice(index, LengthOffset - index).Clear();
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(LengthOffset), hashAlgorithm._byteCount << 3);
		ProcessBlocks(ref hashAlgorithm, buffer);

		BinaryPrimitives.WriteUInt32BigEndian(destination, hashAlgorithm._h0);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), hashAlgorithm._h1);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), hashAlgorithm._h2);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), hashAlgorithm._h3);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(16), hashAlgorithm._h4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlocks(ref Sha1HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source)
	{
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		if (Sha1Arm.Arm64.IsSupported)
		{
			ProcessBlocksArm64(ref hashAlgorithm, source);
			return;
		}

		if (X86Base.X64.IsSupported && Ssse3.IsSupported)
		{
			// Preserve per-block state writeback when a later input block aliases the chaining state.
			if
			(
				source.Length > BlockSizeInBytes
				&& source.Slice(BlockSizeInBytes).Overlaps(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<uint, byte>(ref hashAlgorithm._h0), 5 * sizeof(uint)))
			)
			{
				ProcessBlocksSoftware(ref hashAlgorithm, source);
				return;
			}

			ProcessBlocksSsse3(ref hashAlgorithm, source);
			return;
		}

		ProcessBlocksSoftware(ref hashAlgorithm, source);
	}

	[SkipLocalsInit]
	private static void ProcessBlocksSoftware(ref Sha1HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source)
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

			uint a = hashAlgorithm._h0;
			uint b = hashAlgorithm._h1;
			uint c = hashAlgorithm._h2;
			uint d = hashAlgorithm._h3;
			uint e = hashAlgorithm._h4;

			ChooseFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0);
			ChooseFiveRounds(ref a, ref b, ref c, ref d, ref e, ref Unsafe.Add(ref schedule0, 5));
			ChooseFiveRounds(ref a, ref b, ref c, ref d, ref e, ref Unsafe.Add(ref schedule0, 10));

			ChooseRoundInput(ref a, ref b, ref c, ref d, ref e, Unsafe.Add(ref schedule0, 15) + ChooseConstant);
			ChooseRoundInput(ref e, ref a, ref b, ref c, ref d, Expand(ref schedule0, 16) + ChooseConstant);
			ChooseRoundInput(ref d, ref e, ref a, ref b, ref c, Expand(ref schedule0, 17) + ChooseConstant);
			ChooseRoundInput(ref c, ref d, ref e, ref a, ref b, Expand(ref schedule0, 18) + ChooseConstant);
			ChooseRoundInput(ref b, ref c, ref d, ref e, ref a, Expand(ref schedule0, 19) + ChooseConstant);

			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 20, ParityConstant1);
			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 25, ParityConstant1);
			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 30, ParityConstant1);
			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 35, ParityConstant1);

			MajorityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 40);
			MajorityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 45);
			MajorityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 50);
			MajorityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 55);

			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 60, ParityConstant2);
			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 65, ParityConstant2);
			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 70, ParityConstant2);
			ParityFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0, 75, ParityConstant2);

			hashAlgorithm._h0 += a;
			hashAlgorithm._h1 += b;
			hashAlgorithm._h2 += c;
			hashAlgorithm._h3 += d;
			hashAlgorithm._h4 += e;
			block0 = ref Unsafe.Add(ref block0, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Expand(ref uint words, int round)
	{
		int index = round & 15;
		uint word =
		(
			Unsafe.Add(ref words, round + 13 & 15)
			^ Unsafe.Add(ref words, round + 8 & 15)
			^ Unsafe.Add(ref words, round + 2 & 15)
			^ Unsafe.Add(ref words, index)
		).RotateLeft(1);
		Unsafe.Add(ref words, index) = word;
		return word;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ChooseFiveRounds(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint word0)
	{
		ChooseRoundInput(ref a, ref b, ref c, ref d, ref e, word0 + ChooseConstant);
		ChooseRoundInput(ref e, ref a, ref b, ref c, ref d, Unsafe.Add(ref word0, 1) + ChooseConstant);
		ChooseRoundInput(ref d, ref e, ref a, ref b, ref c, Unsafe.Add(ref word0, 2) + ChooseConstant);
		ChooseRoundInput(ref c, ref d, ref e, ref a, ref b, Unsafe.Add(ref word0, 3) + ChooseConstant);
		ChooseRoundInput(ref b, ref c, ref d, ref e, ref a, Unsafe.Add(ref word0, 4) + ChooseConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ParityFiveRounds(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint words, int round, uint roundConstant)
	{
		ParityRoundInput(ref a, ref b, ref c, ref d, ref e, Expand(ref words, round) + roundConstant);
		ParityRoundInput(ref e, ref a, ref b, ref c, ref d, Expand(ref words, round + 1) + roundConstant);
		ParityRoundInput(ref d, ref e, ref a, ref b, ref c, Expand(ref words, round + 2) + roundConstant);
		ParityRoundInput(ref c, ref d, ref e, ref a, ref b, Expand(ref words, round + 3) + roundConstant);
		ParityRoundInput(ref b, ref c, ref d, ref e, ref a, Expand(ref words, round + 4) + roundConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MajorityFiveRounds(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint words, int round)
	{
		MajorityRoundInput(ref a, ref b, ref c, ref d, ref e, Expand(ref words, round) + MajorityConstant);
		MajorityRoundInput(ref e, ref a, ref b, ref c, ref d, Expand(ref words, round + 1) + MajorityConstant);
		MajorityRoundInput(ref d, ref e, ref a, ref b, ref c, Expand(ref words, round + 2) + MajorityConstant);
		MajorityRoundInput(ref c, ref d, ref e, ref a, ref b, Expand(ref words, round + 3) + MajorityConstant);
		MajorityRoundInput(ref b, ref c, ref d, ref e, ref a, Expand(ref words, round + 4) + MajorityConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ChooseRoundInput(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, uint roundInput)
	{
		e += roundInput;
		e += (c ^ d) & b ^ d;
		e += a.RotateLeft(5);
		b = b.RotateLeft(30);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ParityRoundInput(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, uint roundInput)
	{
		e += roundInput;
		e += b ^ c ^ d;
		e += a.RotateLeft(5);
		b = b.RotateLeft(30);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MajorityRoundInput(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, uint roundInput)
	{
		e += roundInput;
		e += b & c | d & (b | c);
		e += a.RotateLeft(5);
		b = b.RotateLeft(30);
	}
}
