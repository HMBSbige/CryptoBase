namespace CryptoBase.Hashes.MD5;

/// <summary>
/// Provides the MD5 hash core.
/// </summary>
public partial struct MD5HashAlgorithm : IHmacHashCore<MD5HashAlgorithm>
{
	private const int LengthOffset = 56;

	private const int S11 = 7;
	private const int S12 = 12;
	private const int S13 = 17;
	private const int S14 = 22;
	private const int S21 = 5;
	private const int S22 = 9;
	private const int S23 = 14;
	private const int S24 = 20;
	private const int S31 = 4;
	private const int S32 = 11;
	private const int S33 = 16;
	private const int S34 = 23;
	private const int S41 = 6;
	private const int S42 = 10;
	private const int S43 = 15;
	private const int S44 = 21;

	private static ReadOnlySpan<uint> RoundConstants =>
	[
		0xD76AA478U, 0xE8C7B756U, 0x242070DBU, 0xC1BDCEEEU,
		0xF57C0FAFU, 0x4787C62AU, 0xA8304613U, 0xFD469501U,
		0x698098D8U, 0x8B44F7AFU, 0xFFFF5BB1U, 0x895CD7BEU,
		0x6B901122U, 0xFD987193U, 0xA679438EU, 0x49B40821U,
		0xF61E2562U, 0xC040B340U, 0x265E5A51U, 0xE9B6C7AAU,
		0xD62F105DU, 0x02441453U, 0xD8A1E681U, 0xE7D3FBC8U,
		0x21E1CDE6U, 0xC33707D6U, 0xF4D50D87U, 0x455A14EDU,
		0xA9E3E905U, 0xFCEFA3F8U, 0x676F02D9U, 0x8D2A4C8AU,
		0xFFFA3942U, 0x8771F681U, 0x6D9D6122U, 0xFDE5380CU,
		0xA4BEEA44U, 0x4BDECFA9U, 0xF6BB4B60U, 0xBEBFBC70U,
		0x289B7EC6U, 0xEAA127FAU, 0xD4EF3085U, 0x04881D05U,
		0xD9D4D039U, 0xE6DB99E5U, 0x1FA27CF8U, 0xC4AC5665U,
		0xF4292244U, 0x432AFF97U, 0xAB9423A7U, 0xFC93A039U,
		0x655B59C3U, 0x8F0CCC92U, 0xFFEFF47DU, 0x85845DD1U,
		0x6FA87E4FU, 0xFE2CE6E0U, 0xA3014314U, 0x4E0811A1U,
		0xF7537E82U, 0xBD3AF235U, 0x2AD7D2BBU, 0xEB86D391U,
	];

	private uint _a;
	private uint _b;
	private uint _c;
	private uint _d;
	private ulong _byteCount;
	private InlineArray64<byte> _buffer;

	private const int HashSizeInBytes = 16;

	private const int BlockSizeInBytes = 64;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => BlockSizeInBytes;

	[SkipLocalsInit]
	static MD5HashAlgorithm IHashCore<MD5HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out MD5HashAlgorithm hashAlgorithm);
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
			ProcessBlocks(ref this, ref buffer.GetReference(), 1);
			source = source.Slice(bytesNeeded);
		}

		int blockCount = source.Length / BlockSizeInBytes;

		if (blockCount is not 0)
		{
			int byteCount = blockCount * BlockSizeInBytes;
			ProcessBlocks(ref this, ref source.GetReference(), blockCount);
			source = source.Slice(byteCount);
		}

		if (!source.IsEmpty)
		{
			source.CopyTo(buffer);
		}
	}

	private void Reset()
	{
		_a = 0x67452301U;
		_b = 0xEFCDAB89U;
		_c = 0x98BADCFEU;
		_d = 0x10325476U;
		_byteCount = 0;
	}

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		Finalize(ref this, ref destination.GetReference());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		uint selected = c ^ d;
		a += mj + ti;
		selected &= b;
		selected ^= d;
		a += selected;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		a += mj + ti;
		a += c & ~d;
		a += b & d;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint HH(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		uint selected = c ^ d;
		a += mj + ti;
		selected ^= b;
		a += selected;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint II(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		uint selected = ~d;
		a += mj + ti;
		selected |= b;
		selected ^= c;
		a += selected;
		return a.RotateLeft(s) + b;
	}

	private static void Finalize(ref MD5HashAlgorithm hashAlgorithm, ref byte destination)
	{
		int index = (int)(hashAlgorithm._byteCount & BlockSizeInBytes - 1);
		Span<byte> buffer = hashAlgorithm._buffer;
		buffer[index++] = 0x80;

		if (index > LengthOffset)
		{
			buffer.Slice(index).Clear();
			ProcessBlocks(ref hashAlgorithm, ref buffer.GetReference(), 1);
			index = 0;
		}

		buffer.Slice(index, LengthOffset - index).Clear();
		BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(LengthOffset), hashAlgorithm._byteCount << 3);
		ProcessBlocks(ref hashAlgorithm, ref buffer.GetReference(), 1);

		Unsafe.As<MD5HashAlgorithm, Vector128<byte>>(ref hashAlgorithm).StoreUnsafe(ref destination);
	}

	private static void ProcessBlocks(ref MD5HashAlgorithm hashAlgorithm, ref byte source, int blockCount)
	{
		bool subsequentBlockOverlapsState =
			blockCount > 1
			&& MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref source, BlockSizeInBytes), (blockCount - 1) * BlockSizeInBytes)
				.Overlaps(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<uint, byte>(ref hashAlgorithm._a), 4 * sizeof(uint)));

		if (!subsequentBlockOverlapsState && ArmBase.Arm64.IsSupported)
		{
			ProcessBlocksArm64(ref hashAlgorithm, ref source, blockCount);
			return;
		}

		if (!subsequentBlockOverlapsState && X86Base.X64.IsSupported)
		{
			ProcessBlocksX64(ref hashAlgorithm, ref source, blockCount);
			return;
		}

		ProcessBlocksSoftware(ref hashAlgorithm, ref source, blockCount);
	}

	private static void ProcessBlocksSoftware(ref MD5HashAlgorithm hashAlgorithm, ref byte source, int blockCount)
	{
		ref uint roundConstants = ref RoundConstants.GetReference();

		do
		{
			ref InlineArray16<uint> x = ref source.As<InlineArray16<uint>>();

			uint a = hashAlgorithm._a;
			uint b = hashAlgorithm._b;
			uint c = hashAlgorithm._c;
			uint d = hashAlgorithm._d;

			a = FF(a, b, c, d, x[0], S11, Unsafe.Add(ref roundConstants, 0));
			d = FF(d, a, b, c, x[1], S12, Unsafe.Add(ref roundConstants, 1));
			c = FF(c, d, a, b, x[2], S13, Unsafe.Add(ref roundConstants, 2));
			b = FF(b, c, d, a, x[3], S14, Unsafe.Add(ref roundConstants, 3));
			a = FF(a, b, c, d, x[4], S11, Unsafe.Add(ref roundConstants, 4));
			d = FF(d, a, b, c, x[5], S12, Unsafe.Add(ref roundConstants, 5));
			c = FF(c, d, a, b, x[6], S13, Unsafe.Add(ref roundConstants, 6));
			b = FF(b, c, d, a, x[7], S14, Unsafe.Add(ref roundConstants, 7));
			a = FF(a, b, c, d, x[8], S11, Unsafe.Add(ref roundConstants, 8));
			d = FF(d, a, b, c, x[9], S12, Unsafe.Add(ref roundConstants, 9));
			c = FF(c, d, a, b, x[10], S13, Unsafe.Add(ref roundConstants, 10));
			b = FF(b, c, d, a, x[11], S14, Unsafe.Add(ref roundConstants, 11));
			a = FF(a, b, c, d, x[12], S11, Unsafe.Add(ref roundConstants, 12));
			d = FF(d, a, b, c, x[13], S12, Unsafe.Add(ref roundConstants, 13));
			c = FF(c, d, a, b, x[14], S13, Unsafe.Add(ref roundConstants, 14));
			b = FF(b, c, d, a, x[15], S14, Unsafe.Add(ref roundConstants, 15));

			a = GG(a, b, c, d, x[1], S21, Unsafe.Add(ref roundConstants, 16));
			d = GG(d, a, b, c, x[6], S22, Unsafe.Add(ref roundConstants, 17));
			c = GG(c, d, a, b, x[11], S23, Unsafe.Add(ref roundConstants, 18));
			b = GG(b, c, d, a, x[0], S24, Unsafe.Add(ref roundConstants, 19));
			a = GG(a, b, c, d, x[5], S21, Unsafe.Add(ref roundConstants, 20));
			d = GG(d, a, b, c, x[10], S22, Unsafe.Add(ref roundConstants, 21));
			c = GG(c, d, a, b, x[15], S23, Unsafe.Add(ref roundConstants, 22));
			b = GG(b, c, d, a, x[4], S24, Unsafe.Add(ref roundConstants, 23));
			a = GG(a, b, c, d, x[9], S21, Unsafe.Add(ref roundConstants, 24));
			d = GG(d, a, b, c, x[14], S22, Unsafe.Add(ref roundConstants, 25));
			c = GG(c, d, a, b, x[3], S23, Unsafe.Add(ref roundConstants, 26));
			b = GG(b, c, d, a, x[8], S24, Unsafe.Add(ref roundConstants, 27));
			a = GG(a, b, c, d, x[13], S21, Unsafe.Add(ref roundConstants, 28));
			d = GG(d, a, b, c, x[2], S22, Unsafe.Add(ref roundConstants, 29));
			c = GG(c, d, a, b, x[7], S23, Unsafe.Add(ref roundConstants, 30));
			b = GG(b, c, d, a, x[12], S24, Unsafe.Add(ref roundConstants, 31));

			a = HH(a, b, c, d, x[5], S31, Unsafe.Add(ref roundConstants, 32));
			d = HH(d, a, b, c, x[8], S32, Unsafe.Add(ref roundConstants, 33));
			c = HH(c, d, a, b, x[11], S33, Unsafe.Add(ref roundConstants, 34));
			b = HH(b, c, d, a, x[14], S34, Unsafe.Add(ref roundConstants, 35));
			a = HH(a, b, c, d, x[1], S31, Unsafe.Add(ref roundConstants, 36));
			d = HH(d, a, b, c, x[4], S32, Unsafe.Add(ref roundConstants, 37));
			c = HH(c, d, a, b, x[7], S33, Unsafe.Add(ref roundConstants, 38));
			b = HH(b, c, d, a, x[10], S34, Unsafe.Add(ref roundConstants, 39));
			a = HH(a, b, c, d, x[13], S31, Unsafe.Add(ref roundConstants, 40));
			d = HH(d, a, b, c, x[0], S32, Unsafe.Add(ref roundConstants, 41));
			c = HH(c, d, a, b, x[3], S33, Unsafe.Add(ref roundConstants, 42));
			b = HH(b, c, d, a, x[6], S34, Unsafe.Add(ref roundConstants, 43));
			a = HH(a, b, c, d, x[9], S31, Unsafe.Add(ref roundConstants, 44));
			d = HH(d, a, b, c, x[12], S32, Unsafe.Add(ref roundConstants, 45));
			c = HH(c, d, a, b, x[15], S33, Unsafe.Add(ref roundConstants, 46));
			b = HH(b, c, d, a, x[2], S34, Unsafe.Add(ref roundConstants, 47));

			a = II(a, b, c, d, x[0], S41, Unsafe.Add(ref roundConstants, 48));
			d = II(d, a, b, c, x[7], S42, Unsafe.Add(ref roundConstants, 49));
			c = II(c, d, a, b, x[14], S43, Unsafe.Add(ref roundConstants, 50));
			b = II(b, c, d, a, x[5], S44, Unsafe.Add(ref roundConstants, 51));
			a = II(a, b, c, d, x[12], S41, Unsafe.Add(ref roundConstants, 52));
			d = II(d, a, b, c, x[3], S42, Unsafe.Add(ref roundConstants, 53));
			c = II(c, d, a, b, x[10], S43, Unsafe.Add(ref roundConstants, 54));
			b = II(b, c, d, a, x[1], S44, Unsafe.Add(ref roundConstants, 55));
			a = II(a, b, c, d, x[8], S41, Unsafe.Add(ref roundConstants, 56));
			d = II(d, a, b, c, x[15], S42, Unsafe.Add(ref roundConstants, 57));
			c = II(c, d, a, b, x[6], S43, Unsafe.Add(ref roundConstants, 58));
			b = II(b, c, d, a, x[13], S44, Unsafe.Add(ref roundConstants, 59));
			a = II(a, b, c, d, x[4], S41, Unsafe.Add(ref roundConstants, 60));
			d = II(d, a, b, c, x[11], S42, Unsafe.Add(ref roundConstants, 61));
			c = II(c, d, a, b, x[2], S43, Unsafe.Add(ref roundConstants, 62));
			b = II(b, c, d, a, x[9], S44, Unsafe.Add(ref roundConstants, 63));

			hashAlgorithm._a += a;
			hashAlgorithm._b += b;
			hashAlgorithm._c += c;
			hashAlgorithm._d += d;

			source = ref Unsafe.Add(ref source, BlockSizeInBytes);
		} while (--blockCount is not 0);
	}
}
