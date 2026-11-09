using Sha1Arm = System.Runtime.Intrinsics.Arm.Sha1;

namespace CryptoBase.Hashes.Sha1;

/// <summary>
/// Provides the SHA-1 hash core.
/// </summary>
public partial struct Sha1Core : IHmacHashCore<Sha1Core>
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
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => BlockSizeInBytes;

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static Sha1Core IHashCore<Sha1Core>.Create()
	{
		Unsafe.SkipInit(out Sha1Core hashAlgorithm);
		hashAlgorithm._byteCount = 0;
		hashAlgorithm._h0 = 0x67452301U;
		hashAlgorithm._h1 = 0xEFCDAB89U;
		hashAlgorithm._h2 = 0x98BADCFEU;
		hashAlgorithm._h3 = 0x10325476U;
		hashAlgorithm._h4 = 0xC3D2E1F0U;
		return hashAlgorithm;
	}

	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
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

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		Finalize(destination);
	}

	private void Finalize(Span<byte> destination)
	{
		Debug.Assert(destination.Length >= HashLength);

		Span<byte> buffer = _buffer;
		int index = (int)(_byteCount & BlockSizeInBytes - 1);
		buffer[index++] = 0x80;

		if (index > LengthOffset)
		{
			buffer.Slice(index).Clear();
			ProcessBlocks(buffer.AsReadOnlySpan());
			index = 0;
		}

		buffer.Slice(index, LengthOffset - index).Clear();
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(LengthOffset), _byteCount << 3);
		ProcessBlocks(buffer.AsReadOnlySpan());

		ref byte output = ref MemoryMarshal.GetReference(destination);
		Unsafe.WriteUnaligned(ref output, BinaryPrimitives.ReverseEndianness(_h0));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 4), BinaryPrimitives.ReverseEndianness(_h1));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 8), BinaryPrimitives.ReverseEndianness(_h2));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 12), BinaryPrimitives.ReverseEndianness(_h3));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 16), BinaryPrimitives.ReverseEndianness(_h4));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ProcessBlocks(ReadOnlySpan<byte> source)
	{
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		if (Sha1Arm.Arm64.IsSupported)
		{
			ProcessBlocksArm64(source);
			return;
		}

		if (X86Base.X64.IsSupported && Ssse3.IsSupported)
		{
			// Preserve per-block state writeback when a later input block aliases the chaining state.
			if
			(
				source.Length > BlockSizeInBytes
				&& ByteSpans.Overlaps(source.Slice(BlockSizeInBytes), MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<uint, byte>(ref _h0), 5 * sizeof(uint)))
			)
			{
				ProcessBlocksSoftware(source);
				return;
			}

			ProcessBlocksSsse3(source);
			return;
		}

		ProcessBlocksSoftware(source);
	}

	[SkipLocalsInit]
	private void ProcessBlocksSoftware(ReadOnlySpan<byte> source)
	{
		Unsafe.SkipInit(out InlineArray16<uint> schedule);
		ref uint schedule0 = ref schedule[0];
		ref byte block0 = ref MemoryMarshal.GetReference(source);
		int remainingLength = source.Length;

		do
		{
			HashCoreUtils.LoadSixteenBigEndianWords(out schedule0, ref block0);

			uint a = _h0;
			uint b = _h1;
			uint c = _h2;
			uint d = _h3;
			uint e = _h4;

			ChooseFiveRounds(ref a, ref b, ref c, ref d, ref e, ref schedule0);
			ChooseFiveRounds(ref a, ref b, ref c, ref d, ref e, ref Unsafe.Add(ref schedule0, 5));
			ChooseFiveRounds(ref a, ref b, ref c, ref d, ref e, ref Unsafe.Add(ref schedule0, 10));

			Round<Choose>(ref a, ref b, ref c, ref d, ref e, Unsafe.Add(ref schedule0, 15) + ChooseConstant);
			Round<Choose>(ref e, ref a, ref b, ref c, ref d, Expand(ref schedule0, 16) + ChooseConstant);
			Round<Choose>(ref d, ref e, ref a, ref b, ref c, Expand(ref schedule0, 17) + ChooseConstant);
			Round<Choose>(ref c, ref d, ref e, ref a, ref b, Expand(ref schedule0, 18) + ChooseConstant);
			Round<Choose>(ref b, ref c, ref d, ref e, ref a, Expand(ref schedule0, 19) + ChooseConstant);

			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 20, ParityConstant1);
			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 25, ParityConstant1);
			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 30, ParityConstant1);
			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 35, ParityConstant1);

			ExpandedFiveRounds<Majority>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 40, MajorityConstant);
			ExpandedFiveRounds<Majority>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 45, MajorityConstant);
			ExpandedFiveRounds<Majority>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 50, MajorityConstant);
			ExpandedFiveRounds<Majority>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 55, MajorityConstant);

			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 60, ParityConstant2);
			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 65, ParityConstant2);
			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 70, ParityConstant2);
			ExpandedFiveRounds<Parity>(ref a, ref b, ref c, ref d, ref e, ref schedule0, 75, ParityConstant2);

			_h0 += a;
			_h1 += b;
			_h2 += c;
			_h3 += d;
			_h4 += e;
			block0 = ref Unsafe.Add(ref block0, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Expand(ref uint words, int round)
	{
		int index = round & 15;
		uint word = BitOperations.RotateLeft
		(
			Unsafe.Add(ref words, round + 13 & 15)
			^ Unsafe.Add(ref words, round + 8 & 15)
			^ Unsafe.Add(ref words, round + 2 & 15)
			^ Unsafe.Add(ref words, index),
			1
		);
		Unsafe.Add(ref words, index) = word;
		return word;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ChooseFiveRounds(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint word0)
	{
		Round<Choose>(ref a, ref b, ref c, ref d, ref e, word0 + ChooseConstant);
		Round<Choose>(ref e, ref a, ref b, ref c, ref d, Unsafe.Add(ref word0, 1) + ChooseConstant);
		Round<Choose>(ref d, ref e, ref a, ref b, ref c, Unsafe.Add(ref word0, 2) + ChooseConstant);
		Round<Choose>(ref c, ref d, ref e, ref a, ref b, Unsafe.Add(ref word0, 3) + ChooseConstant);
		Round<Choose>(ref b, ref c, ref d, ref e, ref a, Unsafe.Add(ref word0, 4) + ChooseConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandedFiveRounds<TFunction>(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint words, int round, uint roundConstant) where TFunction : IRoundFunction
	{
		Round<TFunction>(ref a, ref b, ref c, ref d, ref e, Expand(ref words, round) + roundConstant);
		Round<TFunction>(ref e, ref a, ref b, ref c, ref d, Expand(ref words, round + 1) + roundConstant);
		Round<TFunction>(ref d, ref e, ref a, ref b, ref c, Expand(ref words, round + 2) + roundConstant);
		Round<TFunction>(ref c, ref d, ref e, ref a, ref b, Expand(ref words, round + 3) + roundConstant);
		Round<TFunction>(ref b, ref c, ref d, ref e, ref a, Expand(ref words, round + 4) + roundConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round<TFunction>(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, uint roundInput) where TFunction : IRoundFunction
	{
		e += roundInput;
		e += TFunction.Mix(b, c, d);
		e += BitOperations.RotateLeft(a, 5);
		b = BitOperations.RotateLeft(b, 30);
	}

	private interface IRoundFunction
	{
		static abstract uint Mix(uint b, uint c, uint d);
	}

	private readonly struct Choose : IRoundFunction
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint Mix(uint b, uint c, uint d)
		{
			return (c ^ d) & b ^ d;
		}
	}

	private readonly struct Parity : IRoundFunction
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint Mix(uint b, uint c, uint d)
		{
			return b ^ c ^ d;
		}
	}

	private readonly struct Majority : IRoundFunction
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint Mix(uint b, uint c, uint d)
		{
			return b & c | d & (b | c);
		}
	}
}
