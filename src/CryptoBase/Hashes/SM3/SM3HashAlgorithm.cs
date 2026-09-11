namespace CryptoBase.Hashes.SM3;

/// <summary>
/// Provides the SM3 hash core.
/// </summary>
/// <seealso href="https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf">SM3 cryptographic hash algorithm</seealso>
public partial struct SM3HashAlgorithm : IHmacHashCore<SM3HashAlgorithm>
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
	public static int HashLengthInBytes => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSizeInBytes => BlockSizeInBytes;

	[SkipLocalsInit]
	static SM3HashAlgorithm IHashCore<SM3HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out SM3HashAlgorithm hashAlgorithm);
		hashAlgorithm.Reset();
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
	private static void AppendBlocks(ref SM3HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source, int bufferedLength, int bytesNeeded)
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Reset()
	{
		_byteCount = 0;
		_v0 = 0x7380166FU;
		_v1 = 0x4914B2B9U;
		_v2 = 0x172442D7U;
		_v3 = 0xDA8A0600U;
		_v4 = 0xA96F30BCU;
		_v5 = 0x163138AAU;
		_v6 = 0xE38DEE4DU;
		_v7 = 0xB0FB0E4EU;
	}

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLengthInBytes, nameof(destination));
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
		return x & y | (x | y) & z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG0(uint x, uint y, uint z)
	{
		return x ^ y ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG1(uint x, uint y, uint z)
	{
		return (y ^ z) & x ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P0(uint x)
	{
		return x ^ x.RotateLeft(9) ^ x.RotateLeft(17);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P1(uint x)
	{
		return x ^ x.RotateLeft(15) ^ x.RotateLeft(23);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> P1(Vector128<uint> value)
	{
		return value ^ (value ^ value.RotateLeftUInt32(8)).RotateLeftUInt32(15);
	}

	[SkipLocalsInit]
	private static void Finalize(ref SM3HashAlgorithm hashAlgorithm, Span<byte> destination)
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

		BinaryPrimitives.WriteUInt32BigEndian(destination, hashAlgorithm._v0);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), hashAlgorithm._v1);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), hashAlgorithm._v2);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), hashAlgorithm._v3);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(16), hashAlgorithm._v4);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(20), hashAlgorithm._v5);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(24), hashAlgorithm._v6);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(28), hashAlgorithm._v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlocks(ref SM3HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source)
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

	[SkipLocalsInit]
	private static void ProcessBlocksSoftware(ref SM3HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source)
	{
		Unsafe.SkipInit(out InlineArray16<uint> schedule);
		ref byte block = ref source.GetReference();
		int remaining = source.Length;

		do
		{
			ProcessSoftware(ref hashAlgorithm, ref block, ref schedule);
			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
			remaining -= BlockSizeInBytes;
		} while (remaining is not 0);
	}

	private static void ProcessSoftware(ref SM3HashAlgorithm hashAlgorithm, ref byte block, ref InlineArray16<uint> schedule)
	{
		ref uint words = ref schedule[0];
		HashCoreUtils.LoadFourBigEndianWords(out words, ref block);
		HashCoreUtils.LoadFourBigEndianWords(out Unsafe.Add(ref words, 4), ref Unsafe.Add(ref block, 16));
		HashCoreUtils.LoadFourBigEndianWords(out Unsafe.Add(ref words, 8), ref Unsafe.Add(ref block, 32));
		HashCoreUtils.LoadFourBigEndianWords(out Unsafe.Add(ref words, 12), ref Unsafe.Add(ref block, 48));

		uint a = hashAlgorithm._v0;
		uint b = hashAlgorithm._v1;
		uint c = hashAlgorithm._v2;
		uint d = hashAlgorithm._v3;
		uint e = hashAlgorithm._v4;
		uint f = hashAlgorithm._v5;
		uint g = hashAlgorithm._v6;
		uint h = hashAlgorithm._v7;
		ref uint roundConstants = ref RoundConstants.GetReference();

		for (int round = 0; round < 16; round += 4)
		{
			uint word = Unsafe.Add(ref words, round & 15);
			d = RoundSoftwareEarly(a, b, c, d, e, f, g, h, word, word ^ Unsafe.Add(ref words, round + 4 & 15), Unsafe.Add(ref roundConstants, round), out h);
			b = b.RotateLeft(9);
			f = f.RotateLeft(19);
			ExpandSoftware(ref words, round + 16);

			word = Unsafe.Add(ref words, round + 1 & 15);
			c = RoundSoftwareEarly(d, a, b, c, h, e, f, g, word, word ^ Unsafe.Add(ref words, round + 5 & 15), Unsafe.Add(ref roundConstants, round + 1), out g);
			a = a.RotateLeft(9);
			e = e.RotateLeft(19);
			ExpandSoftware(ref words, round + 17);

			word = Unsafe.Add(ref words, round + 2 & 15);
			b = RoundSoftwareEarly(c, d, a, b, g, h, e, f, word, word ^ Unsafe.Add(ref words, round + 6 & 15), Unsafe.Add(ref roundConstants, round + 2), out f);
			d = d.RotateLeft(9);
			h = h.RotateLeft(19);
			ExpandSoftware(ref words, round + 18);

			word = Unsafe.Add(ref words, round + 3 & 15);
			a = RoundSoftwareEarly(b, c, d, a, f, g, h, e, word, word ^ Unsafe.Add(ref words, round + 7 & 15), Unsafe.Add(ref roundConstants, round + 3), out e);
			c = c.RotateLeft(9);
			g = g.RotateLeft(19);
			ExpandSoftware(ref words, round + 19);
		}

		for (int round = 16; round < 52; round += 4)
		{
			uint word = Unsafe.Add(ref words, round & 15);
			d = RoundSoftwareLate(a, b, c, d, e, f, g, h, word, word ^ Unsafe.Add(ref words, round + 4 & 15), Unsafe.Add(ref roundConstants, round), out h);
			b = b.RotateLeft(9);
			f = f.RotateLeft(19);
			ExpandSoftware(ref words, round + 16);

			word = Unsafe.Add(ref words, round + 1 & 15);
			c = RoundSoftwareLate(d, a, b, c, h, e, f, g, word, word ^ Unsafe.Add(ref words, round + 5 & 15), Unsafe.Add(ref roundConstants, round + 1), out g);
			a = a.RotateLeft(9);
			e = e.RotateLeft(19);
			ExpandSoftware(ref words, round + 17);

			word = Unsafe.Add(ref words, round + 2 & 15);
			b = RoundSoftwareLate(c, d, a, b, g, h, e, f, word, word ^ Unsafe.Add(ref words, round + 6 & 15), Unsafe.Add(ref roundConstants, round + 2), out f);
			d = d.RotateLeft(9);
			h = h.RotateLeft(19);
			ExpandSoftware(ref words, round + 18);

			word = Unsafe.Add(ref words, round + 3 & 15);
			a = RoundSoftwareLate(b, c, d, a, f, g, h, e, word, word ^ Unsafe.Add(ref words, round + 7 & 15), Unsafe.Add(ref roundConstants, round + 3), out e);
			c = c.RotateLeft(9);
			g = g.RotateLeft(19);
			ExpandSoftware(ref words, round + 19);
		}

		for (int round = 52; round < 64; round += 4)
		{
			uint word = Unsafe.Add(ref words, round & 15);
			d = RoundSoftwareLate(a, b, c, d, e, f, g, h, word, word ^ Unsafe.Add(ref words, round + 4 & 15), Unsafe.Add(ref roundConstants, round), out h);
			b = b.RotateLeft(9);
			f = f.RotateLeft(19);

			word = Unsafe.Add(ref words, round + 1 & 15);
			c = RoundSoftwareLate(d, a, b, c, h, e, f, g, word, word ^ Unsafe.Add(ref words, round + 5 & 15), Unsafe.Add(ref roundConstants, round + 1), out g);
			a = a.RotateLeft(9);
			e = e.RotateLeft(19);

			word = Unsafe.Add(ref words, round + 2 & 15);
			b = RoundSoftwareLate(c, d, a, b, g, h, e, f, word, word ^ Unsafe.Add(ref words, round + 6 & 15), Unsafe.Add(ref roundConstants, round + 2), out f);
			d = d.RotateLeft(9);
			h = h.RotateLeft(19);

			word = Unsafe.Add(ref words, round + 3 & 15);
			a = RoundSoftwareLate(b, c, d, a, f, g, h, e, word, word ^ Unsafe.Add(ref words, round + 7 & 15), Unsafe.Add(ref roundConstants, round + 3), out e);
			c = c.RotateLeft(9);
			g = g.RotateLeft(19);
		}

		hashAlgorithm._v0 ^= a;
		hashAlgorithm._v1 ^= b;
		hashAlgorithm._v2 ^= c;
		hashAlgorithm._v3 ^= d;
		hashAlgorithm._v4 ^= e;
		hashAlgorithm._v5 ^= f;
		hashAlgorithm._v6 ^= g;
		hashAlgorithm._v7 ^= h;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint ExpandSoftware(ref uint words, int round)
	{
		int index = round & 15;
		uint word = P1(Unsafe.Add(ref words, index) ^ Unsafe.Add(ref words, round - 9 & 15) ^ Unsafe.Add(ref words, round - 3 & 15).RotateLeft(15))
					^ Unsafe.Add(ref words, round - 13 & 15).RotateLeft(7)
					^ Unsafe.Add(ref words, round - 6 & 15);
		Unsafe.Add(ref words, index) = word;
		return word;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RoundSoftwareEarly(uint a, uint b, uint c, uint d, uint e, uint f, uint g, uint h, uint word, uint mixed, uint constant, out uint nextH)
	{
		uint a12 = a.RotateLeft(12);
		uint ss1 = (a12 + e + constant).RotateLeft(7);
		nextH = P0(GG0(e, f, g) + h + ss1 + word);
		return FF0(a, b, c) + d + (ss1 ^ a12) + mixed;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint RoundSoftwareLate(uint a, uint b, uint c, uint d, uint e, uint f, uint g, uint h, uint word, uint mixed, uint constant, out uint nextH)
	{
		uint a12 = a.RotateLeft(12);
		uint ss1 = (a12 + e + constant).RotateLeft(7);
		nextH = P0(GG1(e, f, g) + h + ss1 + word);
		return FF1(a, b, c) + d + (ss1 ^ a12) + mixed;
	}
}
