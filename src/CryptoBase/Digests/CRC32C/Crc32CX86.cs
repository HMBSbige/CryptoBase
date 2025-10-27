namespace CryptoBase.Digests.CRC32C;

/// <summary>
/// Same as <see cref="Crc32X86" /> , but different constants.
/// </summary>
public class Crc32CX86 : IHash
{
	public string Name => @"CRC-32C";

	public int Length => HashConstants.Crc32Length;

	public int BlockSize => HashConstants.Crc32BlockSize;

	public static bool IsSupport => Sse42.IsSupported || Sse2.IsSupported && Pclmulqdq.IsSupported;

	private uint _state;

	#region Constants

	private static readonly Vector128<ulong> K1K2 = Crc32Table.K1K2C;
	private static readonly Vector128<ulong> K3K4 = Crc32Table.K3K4C;
	private static readonly Vector128<ulong> K5 = Crc32Table.K5C;
	private static readonly Vector128<ulong> RU = Crc32Table.RUC;
	private static readonly Vector128<ulong> Mask32 = Crc32Table.Mask32;

	#endregion

	public Crc32CX86()
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
		if (Sse2.IsSupported && Pclmulqdq.IsSupported && source.Length >= 64)
		{
			_state = Update(source, _state);
			source = source.Slice(source.Length - source.Length % 0x10);
		}

		if (Sse42.IsSupported)
		{
			UpdateSse42(source);
		}
		else
		{
			_state = ~Crc32Table.Crc32C.Append(~_state, source);
		}
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
			Vector128<ulong> t1 = Pclmulqdq.CarrylessMultiply(x1, K1K2, 0x11);
			Vector128<ulong> t2 = Pclmulqdq.CarrylessMultiply(x2, K1K2, 0x11);
			Vector128<ulong> t3 = Pclmulqdq.CarrylessMultiply(x3, K1K2, 0x11);
			Vector128<ulong> t4 = Pclmulqdq.CarrylessMultiply(x4, K1K2, 0x11);

			x1 = Pclmulqdq.CarrylessMultiply(x1, K1K2, 0x00);
			x2 = Pclmulqdq.CarrylessMultiply(x2, K1K2, 0x00);
			x3 = Pclmulqdq.CarrylessMultiply(x3, K1K2, 0x00);
			x4 = Pclmulqdq.CarrylessMultiply(x4, K1K2, 0x00);

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

		Vector128<ulong> t = Pclmulqdq.CarrylessMultiply(x1, K3K4, 0x11);
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
			x1 = Sse2.Xor(x1, Unsafe.As<byte, Vector128<ulong>>(ref Unsafe.Add(ref ptr, offset)));

			length -= 0x10;
			offset += 0x10;
		}

		Vector128<ulong> r4 = Pclmulqdq.CarrylessMultiply(K3K4, x1, 0x01);
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
		return x1.AsUInt32().GetElement(1);// pextrd eax, x1, 1
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateSse42(ReadOnlySpan<byte> source)
	{
		int length = source.Length;
		int offset = 0;
		ref byte sourceRef = ref source.GetReference();
		ref uint state = ref _state;

		if (Sse42.X64.IsSupported)
		{
			while (length >= 8)
			{
				ref ulong data = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref sourceRef, offset));
				state = (uint)Sse42.X64.Crc32(state, data);
				offset += 8;
				length -= 8;
			}

			if (length >= 4)
			{
				ref uint data = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref sourceRef, offset));
				state = Sse42.Crc32(state, data);
				offset += 4;
				length -= 4;
			}
		}
		else
		{
			while (length >= 4)
			{
				ref uint data = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref sourceRef, offset));
				state = Sse42.Crc32(state, data);
				offset += 4;
				length -= 4;
			}
		}

		if (length >= 2)
		{
			ref ushort data = ref Unsafe.As<byte, ushort>(ref Unsafe.Add(ref sourceRef, offset));
			state = Sse42.Crc32(state, data);
			offset += 2;
			length -= 2;
		}

		if (length > 0)
		{
			state = Sse42.Crc32(state, Unsafe.Add(ref sourceRef, offset));
		}
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
