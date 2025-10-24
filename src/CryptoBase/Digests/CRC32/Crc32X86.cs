namespace CryptoBase.Digests.CRC32;

/// <summary>
/// https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/fast-crc-computation-generic-polynomials-pclmulqdq-paper.pdf
/// </summary>
public class Crc32X86 : IHash
{
	public string Name => @"CRC-32";

	public int Length => HashConstants.Crc32Length;

	public int BlockSize => HashConstants.Crc32BlockSize;

	public static bool IsSupport => Sse2.IsSupported && Pclmulqdq.IsSupported;

	private uint _state;

	#region Constants

	private static readonly Vector128<ulong> K1K2 = Crc32Table.K1K2;
	private static readonly Vector128<ulong> K3K4 = Crc32Table.K3K4;
	private static readonly Vector128<ulong> K5 = Crc32Table.K5;
	private static readonly Vector128<ulong> RU = Crc32Table.RU;
	private static readonly Vector128<ulong> Mask32 = Crc32Table.Mask32;

	#endregion

	public Crc32X86()
	{
		Reset();
	}

	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Update(origin);
		GetHash(destination);
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		if (source.Length >= 64)
		{
			_state = Update(source, source.Length, _state);
			source = source[^(source.Length % 0x10)..];
		}

		_state = ~Crc32Table.Crc32.Append(~_state, source);
	}

	public void GetHash(Span<byte> destination)
	{
		BinaryPrimitives.WriteUInt32BigEndian(destination, ~_state);
		Reset();
	}

	public void Reset()
	{
		_state = uint.MaxValue;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint Update(ReadOnlySpan<byte> buffer, int length, uint crc)
	{
		ref byte bufferRef = ref MemoryMarshal.GetReference(buffer);
		var x1 = Unsafe.ReadUnaligned<Vector128<ulong>>(ref bufferRef).AsUInt64();
		var x2 = Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, 0x10)).AsUInt64();
		var x3 = Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, 0x20)).AsUInt64();
		var x4 = Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, 0x30)).AsUInt64();
		var vCrc = Vector128.CreateScalar(crc).AsUInt64();
		x1 = Sse2.Xor(x1, vCrc);

		length -= 0x40;
		int offset = 0x40;

		while (length >= 0x40)
		{
			var t1 = Pclmulqdq.CarrylessMultiply(x1, K1K2, 0x11);
			var t2 = Pclmulqdq.CarrylessMultiply(x2, K1K2, 0x11);
			var t3 = Pclmulqdq.CarrylessMultiply(x3, K1K2, 0x11);
			var t4 = Pclmulqdq.CarrylessMultiply(x4, K1K2, 0x11);

			x1 = Pclmulqdq.CarrylessMultiply(x1, K1K2, 0x00);
			x2 = Pclmulqdq.CarrylessMultiply(x2, K1K2, 0x00);
			x3 = Pclmulqdq.CarrylessMultiply(x3, K1K2, 0x00);
			x4 = Pclmulqdq.CarrylessMultiply(x4, K1K2, 0x00);

			x1 = Sse2.Xor(x1, t1);
			x2 = Sse2.Xor(x2, t2);
			x3 = Sse2.Xor(x3, t3);
			x4 = Sse2.Xor(x4, t4);

			x1 = Sse2.Xor(x1, Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, offset)).AsUInt64());
			x2 = Sse2.Xor(x2, Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, offset + 0x10)).AsUInt64());
			x3 = Sse2.Xor(x3, Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, offset + 0x20)).AsUInt64());
			x4 = Sse2.Xor(x4, Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, offset + 0x30)).AsUInt64());

			length -= 0x40;
			offset += 0x40;
		}

		var t = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x11);
		x1 = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x00);
		x1 = Sse2.Xor(x1, t);
		x1 = Sse2.Xor(x1, x2);

		t = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x11);
		x1 = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x00);
		x1 = Sse2.Xor(x1, t);
		x1 = Sse2.Xor(x1, x3);

		t = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x11);
		x1 = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x00);
		x1 = Sse2.Xor(x1, t);
		x1 = Sse2.Xor(x1, x4);

		while (length >= 0x10)
		{
			t = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x11);
			x1 = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x00);
			x1 = Sse2.Xor(x1, t);
			x1 = Sse2.Xor(x1, Unsafe.ReadUnaligned<Vector128<ulong>>(ref Unsafe.Add(ref bufferRef, offset)).AsUInt64());

			length -= 0x10;
			offset += 0x10;
		}

		var r4 = Pclmulqdq.CarrylessMultiply(K3K4, x1, 0x01);
		x1 = Sse2.ShiftRightLogical128BitLane(x1, 0x08);
		x1 = Sse2.Xor(x1, r4);

		t = Sse2.ShiftRightLogical128BitLane(x1, 0x04);
		x1 = Sse2.And(x1, Mask32);
		x1 = Pclmulqdq.CarrylessMultiply(x1, K5, 0x00);
		x1 = Sse2.Xor(x1, t);

		t = x1;
		x1 = Sse2.And(x1, Mask32);
		x1 = Pclmulqdq.CarrylessMultiply(x1, RU, 0x10);
		x1 = Sse2.And(x1, Mask32);
		x1 = Pclmulqdq.CarrylessMultiply(x1, RU, 0x00);
		x1 = Sse2.Xor(x1, t);
		return x1.AsUInt32().GetElement(1); // pextrd eax, x1, 1
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
