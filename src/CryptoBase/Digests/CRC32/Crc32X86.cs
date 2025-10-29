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
			_state = Update(source, _state);
			source = source.Slice(source.Length - source.Length % 0x10);
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
	private static uint Update(ReadOnlySpan<byte> buffer, uint crc)
	{
		Vector128<ulong> k1k2 = Crc32Table.K1K2;
		Vector128<ulong> k3k4 = Crc32Table.K3K4;
		Vector128<ulong> k5 = Crc32Table.K5;
		Vector128<ulong> ru = Crc32Table.RU;
		Vector128<ulong> mask32 = Crc32Table.Mask32;
		int length = buffer.Length;
		ref byte ptr = ref buffer.GetReference();

		ref Vector128<ulong> x1 = ref Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, 0 * 0x10));
		ref Vector128<ulong> x2 = ref Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, 1 * 0x10));
		ref Vector128<ulong> x3 = ref Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, 2 * 0x10));
		ref Vector128<ulong> x4 = ref Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, 3 * 0x10));
		Vector128<ulong> vCrc = Vector128.CreateScalar(crc).AsUInt64();
		x1 = Sse2.Xor(x1, vCrc);

		length -= 0x40;
		int offset = 0x40;

		while (length >= 0x40)
		{
			Vector128<ulong> t1 = Pclmulqdq.CarrylessMultiply(x1, k1k2, 0x11);
			Vector128<ulong> t2 = Pclmulqdq.CarrylessMultiply(x2, k1k2, 0x11);
			Vector128<ulong> t3 = Pclmulqdq.CarrylessMultiply(x3, k1k2, 0x11);
			Vector128<ulong> t4 = Pclmulqdq.CarrylessMultiply(x4, k1k2, 0x11);

			x1 = Pclmulqdq.CarrylessMultiply(x1, k1k2, 0x00);
			x2 = Pclmulqdq.CarrylessMultiply(x2, k1k2, 0x00);
			x3 = Pclmulqdq.CarrylessMultiply(x3, k1k2, 0x00);
			x4 = Pclmulqdq.CarrylessMultiply(x4, k1k2, 0x00);

			x1 = Sse2.Xor(x1, t1);
			x2 = Sse2.Xor(x2, t2);
			x3 = Sse2.Xor(x3, t3);
			x4 = Sse2.Xor(x4, t4);

			x1 = Sse2.Xor(x1, Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, offset)));
			offset += 0x10;
			x2 = Sse2.Xor(x2, Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, offset)));
			offset += 0x10;
			x3 = Sse2.Xor(x3, Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, offset)));
			offset += 0x10;
			x4 = Sse2.Xor(x4, Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, offset)));
			offset += 0x10;

			length -= 0x40;
		}

		Vector128<ulong> t = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x11);
		x1 = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x00);
		x1 = Sse2.Xor(x1, t);
		x1 = Sse2.Xor(x1, x2);

		t = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x11);
		x1 = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x00);
		x1 = Sse2.Xor(x1, t);
		x1 = Sse2.Xor(x1, x3);

		t = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x11);
		x1 = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x00);
		x1 = Sse2.Xor(x1, t);
		x1 = Sse2.Xor(x1, x4);

		while (length >= 0x10)
		{
			t = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x11);
			x1 = Pclmulqdq.CarrylessMultiply(x1, k3k4, 0x00);
			x1 = Sse2.Xor(x1, t);
			x1 = Sse2.Xor(x1, Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, offset)));

			length -= 0x10;
			offset += 0x10;
		}

		Vector128<ulong> r4 = Pclmulqdq.CarrylessMultiply(k3k4, x1, 0x01);
		x1 = Sse2.ShiftRightLogical128BitLane(x1, 0x08);
		x1 = Sse2.Xor(x1, r4);

		t = Sse2.ShiftRightLogical128BitLane(x1, 0x04);
		x1 = Sse2.And(x1, mask32);
		x1 = Pclmulqdq.CarrylessMultiply(x1, k5, 0x00);
		x1 = Sse2.Xor(x1, t);

		t = x1;
		x1 = Sse2.And(x1, mask32);
		x1 = Pclmulqdq.CarrylessMultiply(x1, ru, 0x10);
		x1 = Sse2.And(x1, mask32);
		x1 = Pclmulqdq.CarrylessMultiply(x1, ru, 0x00);
		x1 = Sse2.Xor(x1, t);
		return x1.AsUInt32().GetElement(1);// pextrd eax, x1, 1
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
