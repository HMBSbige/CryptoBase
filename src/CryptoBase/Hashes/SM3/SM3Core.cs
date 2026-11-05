namespace CryptoBase.Hashes.SM3;

/// <summary>
/// Provides the SM3 hash core.
/// </summary>
/// <seealso href="https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf">SM3 cryptographic hash algorithm</seealso>
public partial struct SM3Core : IHmacHashCore<SM3Core>
{
	private const int LengthOffset = 56;
	private const int HashSizeInBytes = 32;

	private static ReadOnlySpan<uint> RoundConstants =>
	[
		0x79CC4519U, 0xF3988A32U, 0xE7311465U, 0xCE6228CBU, 0x9CC45197U, 0x3988A32FU, 0x7311465EU, 0xE6228CBCU,
		0xCC451979U, 0x988A32F3U, 0x311465E7U, 0x6228CBCEU, 0xC451979CU, 0x88A32F39U, 0x11465E73U, 0x228CBCE6U,
		0x9D8A7A87U, 0x3B14F50FU, 0x7629EA1EU, 0xEC53D43CU, 0xD8A7A879U, 0xB14F50F3U, 0x629EA1E7U, 0xC53D43CEU,
		0x8A7A879DU, 0x14F50F3BU, 0x29EA1E76U, 0x53D43CECU, 0xA7A879D8U, 0x4F50F3B1U, 0x9EA1E762U, 0x3D43CEC5U,
		0x7A879D8AU, 0xF50F3B14U, 0xEA1E7629U, 0xD43CEC53U, 0xA879D8A7U, 0x50F3B14FU, 0xA1E7629EU, 0x43CEC53DU,
		0x879D8A7AU, 0x0F3B14F5U, 0x1E7629EAU, 0x3CEC53D4U, 0x79D8A7A8U, 0xF3B14F50U, 0xE7629EA1U, 0xCEC53D43U,
		0x9D8A7A87U, 0x3B14F50FU, 0x7629EA1EU, 0xEC53D43CU, 0xD8A7A879U, 0xB14F50F3U, 0x629EA1E7U, 0xC53D43CEU,
		0x8A7A879DU, 0x14F50F3BU, 0x29EA1E76U, 0x53D43CECU, 0xA7A879D8U, 0x4F50F3B1U, 0x9EA1E762U, 0x3D43CEC5U,
	];

	private ulong _byteCount;
	private uint _v0;
	private uint _v1;
	private uint _v2;
	private uint _v3;
	private uint _v4;
	private uint _v5;
	private uint _v6;
	private uint _v7;
	private InlineArray64<byte> _buffer;

	private const int BlockSizeInBytes = 64;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => BlockSizeInBytes;

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static SM3Core IHashCore<SM3Core>.Create()
	{
		Unsafe.SkipInit(out SM3Core hashAlgorithm);
		hashAlgorithm._byteCount = 0;
		hashAlgorithm._v0 = 0x7380166FU;
		hashAlgorithm._v1 = 0x4914B2B9U;
		hashAlgorithm._v2 = 0x172442D7U;
		hashAlgorithm._v3 = 0xDA8A0600U;
		hashAlgorithm._v4 = 0xA96F30BCU;
		hashAlgorithm._v5 = 0x163138AAU;
		hashAlgorithm._v6 = 0xE38DEE4DU;
		hashAlgorithm._v7 = 0xB0FB0E4EU;
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

		AppendBlocks(ref this, source, bufferedLength, bytesNeeded);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void AppendBlocks(ref SM3Core hashAlgorithm, ReadOnlySpan<byte> source, int bufferedLength, int bytesNeeded)
	{
		Span<byte> buffer = hashAlgorithm._buffer;

		if (bufferedLength is not 0)
		{
			source.Slice(0, bytesNeeded).CopyTo(buffer.Slice(bufferedLength));
			ProcessBlocks(ref hashAlgorithm, buffer);
			source = source.Slice(bytesNeeded);
		}

		int completeLength = source.Length & ~(BlockSizeInBytes - 1);

		if (completeLength is not 0)
		{
			ProcessBlocks(ref hashAlgorithm, source.Slice(0, completeLength));
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
		Finalize(ref this, destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF0(uint x, uint y, uint z)
	{
		return x ^ y ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF1(uint x, uint y, uint z)
	{
		return x & (y | z) | y & z;
	}

	// yz = y ^ z is ready before x.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG0(uint x, uint yz)
	{
		return x ^ yz;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG1(uint x, uint yz, uint z)
	{
		return yz & x ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P0(uint x)
	{
		return x ^ BitOperations.RotateLeft(x, 9) ^ BitOperations.RotateLeft(x, 17);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P1(uint x)
	{
		return x ^ BitOperations.RotateLeft(x, 15) ^ BitOperations.RotateLeft(x, 23);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> P1(Vector128<uint> value)
	{
		return value ^ (value ^ value.RotateLeftUInt32(8)).RotateLeftUInt32(15);
	}

	[SkipLocalsInit]
	private static void Finalize(ref SM3Core hashAlgorithm, Span<byte> destination)
	{
		Debug.Assert(destination.Length >= HashLength);

		Span<byte> buffer = hashAlgorithm._buffer;
		int index = (int)(hashAlgorithm._byteCount & BlockSizeInBytes - 1);
		buffer[index++] = 0x80;

		if (index > LengthOffset)
		{
			buffer.Slice(index).Clear();
			ProcessBlocks(ref hashAlgorithm, buffer.AsReadOnlySpan());
			index = 0;
		}

		buffer.Slice(index, LengthOffset - index).Clear();
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(LengthOffset), hashAlgorithm._byteCount << 3);
		ProcessBlocks(ref hashAlgorithm, buffer.AsReadOnlySpan());

		ref byte output = ref MemoryMarshal.GetReference(destination);
		Unsafe.WriteUnaligned(ref output, BinaryPrimitives.ReverseEndianness(hashAlgorithm._v0));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 4), BinaryPrimitives.ReverseEndianness(hashAlgorithm._v1));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 8), BinaryPrimitives.ReverseEndianness(hashAlgorithm._v2));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 12), BinaryPrimitives.ReverseEndianness(hashAlgorithm._v3));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 16), BinaryPrimitives.ReverseEndianness(hashAlgorithm._v4));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 20), BinaryPrimitives.ReverseEndianness(hashAlgorithm._v5));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 24), BinaryPrimitives.ReverseEndianness(hashAlgorithm._v6));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 28), BinaryPrimitives.ReverseEndianness(hashAlgorithm._v7));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlocks(ref SM3Core hashAlgorithm, ReadOnlySpan<byte> source)
	{
		Debug.Assert(!source.IsEmpty);
		Debug.Assert(source.Length % BlockSizeInBytes is 0);

		if (X86Base.X64.IsSupported && Ssse3.IsSupported)
		{
			ProcessBlocksX86(ref hashAlgorithm, source);
			return;
		}

		ProcessBlocksSoftware(ref hashAlgorithm, source);
	}

	private static void ProcessBlocksSoftware(ref SM3Core hashAlgorithm, ReadOnlySpan<byte> source)
	{
		ProcessBlocksSoftware(ref hashAlgorithm, ref MemoryMarshal.GetReference(source), source.Length, 23, 15);
	}

	// The schedule holds W[0..67] in order, so each access is a constant offset from words.
	// rotate23 and rotate15 are 23 and 15, passed in for P0Software.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ProcessBlocksSoftware(ref SM3Core hashAlgorithm, ref byte block, int remaining, int rotate23, int rotate15)
	{
		Unsafe.SkipInit(out SM3Schedule schedule);
		uint a = hashAlgorithm._v0;
		uint b = hashAlgorithm._v1;
		uint c = hashAlgorithm._v2;
		uint d = hashAlgorithm._v3;
		uint e = hashAlgorithm._v4;
		uint f = hashAlgorithm._v5;
		uint g = hashAlgorithm._v6;
		uint h = hashAlgorithm._v7;

		do
		{
			ref uint words = ref schedule[0];
			HashCoreUtils.LoadSixteenBigEndianWords(out words, ref block);
			ref uint roundConstants = ref MemoryMarshal.GetReference(RoundConstants);

			for (int round = 0; round < 16; round += 4)
			{
				Round4Software(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref words, ref roundConstants, false, true, rotate23, rotate15);
				words = ref Unsafe.Add(ref words, 4);
				roundConstants = ref Unsafe.Add(ref roundConstants, 4);
			}

			for (int round = 16; round < 52; round += 4)
			{
				Round4Software(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref words, ref roundConstants, true, true, rotate23, rotate15);
				words = ref Unsafe.Add(ref words, 4);
				roundConstants = ref Unsafe.Add(ref roundConstants, 4);
			}

			for (int round = 52; round < 64; round += 4)
			{
				Round4Software(ref a, ref b, ref c, ref d, ref e, ref f, ref g, ref h, ref words, ref roundConstants, true, false, rotate23, rotate15);
				words = ref Unsafe.Add(ref words, 4);
				roundConstants = ref Unsafe.Add(ref roundConstants, 4);
			}

			hashAlgorithm._v0 = a ^= hashAlgorithm._v0;
			hashAlgorithm._v1 = b ^= hashAlgorithm._v1;
			hashAlgorithm._v2 = c ^= hashAlgorithm._v2;
			hashAlgorithm._v3 = d ^= hashAlgorithm._v3;
			hashAlgorithm._v4 = e ^= hashAlgorithm._v4;
			hashAlgorithm._v5 = f ^= hashAlgorithm._v5;
			hashAlgorithm._v6 = g ^= hashAlgorithm._v6;
			hashAlgorithm._v7 = h ^= hashAlgorithm._v7;

			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
			remaining -= BlockSizeInBytes;
		} while (remaining is not 0);
	}

	// Rounds j..j+3 with words = &W[j] and roundConstants = &T[j]; expand also writes W[j+16..j+19].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round4Software(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e, ref uint f, ref uint g, ref uint h, ref uint words, ref uint roundConstants, bool late, bool expand, int rotate23, int rotate15)
	{
		uint word = words;
		d = RoundSoftware(a, b, c, d, e, f, g, h, word, word ^ Unsafe.Add(ref words, 4), roundConstants, late, rotate23, rotate15, out h);
		b = BitOperations.RotateLeft(b, 9);
		f = BitOperations.RotateLeft(f, 19);

		if (expand)
		{
			ExpandSoftware(ref words);
		}

		word = Unsafe.Add(ref words, 1);
		c = RoundSoftware(d, a, b, c, h, e, f, g, word, word ^ Unsafe.Add(ref words, 5), Unsafe.Add(ref roundConstants, 1), late, rotate23, rotate15, out g);
		a = BitOperations.RotateLeft(a, 9);
		e = BitOperations.RotateLeft(e, 19);

		if (expand)
		{
			ExpandSoftware(ref Unsafe.Add(ref words, 1));
		}

		word = Unsafe.Add(ref words, 2);
		b = RoundSoftware(c, d, a, b, g, h, e, f, word, word ^ Unsafe.Add(ref words, 6), Unsafe.Add(ref roundConstants, 2), late, rotate23, rotate15, out f);
		d = BitOperations.RotateLeft(d, 9);
		h = BitOperations.RotateLeft(h, 19);

		if (expand)
		{
			ExpandSoftware(ref Unsafe.Add(ref words, 2));
		}

		word = Unsafe.Add(ref words, 3);
		a = RoundSoftware(b, c, d, a, f, g, h, e, word, word ^ Unsafe.Add(ref words, 7), Unsafe.Add(ref roundConstants, 3), late, rotate23, rotate15, out e);
		c = BitOperations.RotateLeft(c, 9);
		g = BitOperations.RotateLeft(g, 19);

		if (expand)
		{
			ExpandSoftware(ref Unsafe.Add(ref words, 3));
		}
	}

	// W[j+16] for words = &W[j].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandSoftware(ref uint words)
	{
		Unsafe.Add(ref words, 16) = P1(words ^ Unsafe.Add(ref words, 7) ^ BitOperations.RotateLeft(Unsafe.Add(ref words, 13), 15))
			^ BitOperations.RotateLeft(Unsafe.Add(ref words, 3), 7)
			^ Unsafe.Add(ref words, 10);
	}

	// For the x86 kernel, which never takes the ARM64 branch of P0Software.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RoundSoftware(uint a, uint b, uint c, uint d, uint e, uint f, uint g, uint h, uint word, uint mixed, uint constant, bool late, out uint nextH)
	{
		return RoundSoftware(a, b, c, d, e, f, g, h, word, mixed, constant, late, 23, 15, out nextH);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RoundSoftware(uint a, uint b, uint c, uint d, uint e, uint f, uint g, uint h, uint word, uint mixed, uint constant, bool late, int rotate23, int rotate15, out uint nextH)
	{
		// e arrives last: one add before the rotate, and SS1 added last.
		// Within one expression the JIT re-associates these sums, so they are separate statements, none directly before its only use (forward substitution).
		uint a12 = BitOperations.RotateLeft(a, 12);
		uint fg = f ^ g;
		uint a12K = a12 + constant;
		uint hW = h + word;
		uint dW = d + mixed;
		uint ss1 = BitOperations.RotateLeft(e + a12K, 7);
		uint gg = late ? GG1(e, fg, g) : GG0(e, fg);
		uint ff = late ? FF1(a, b, c) : FF0(a, b, c);
		uint tt2Partial = gg + hW;
		uint tt1Partial = ff + dW;
		nextH = P0Software(tt2Partial + ss1, rotate23, rotate15);
		return (ss1 ^ a12) + tt1Partial;
	}

	// ARM64 folds rotates by constants into eor with a rotated operand, which can take 2 cycles each, so P0 would take 4 instead of 3.
	// The amounts must therefore come from arguments of a method that is never inlined.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P0Software(uint x, int rotate23, int rotate15)
	{
		if (ArmBase.Arm64.IsSupported)
		{
			return x ^ BitOperations.RotateRight(x, rotate23) ^ BitOperations.RotateRight(x, rotate15);
		}

		return P0(x);
	}
}
