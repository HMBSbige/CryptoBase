using System.Numerics;

namespace CryptoBase.Digests.CRC32C;

public class Crc32C : IHash
{
	public string Name => @"CRC-32C";

	public int Length => HashConstants.Crc32Length;

	public int BlockSize => HashConstants.Crc32BlockSize;

	private uint _state;

	public Crc32C()
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
		if (Sse42.X64.IsSupported || Crc32.Arm64.IsSupported)
		{
			UpdateDefault(source);
			return;
		}

		if (Sse2.IsSupported && Pclmulqdq.IsSupported && source.Length >= 64)
		{
			_state = Update(source, _state);
			source = source.Slice(source.Length - source.Length % 0x10);
		}

		UpdateDefault(source);
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
		// Constants for CRC32C
		Vector128<ulong> k1k2 = Vector128.Create(0x00000000740eef02, 0x000000009e4addf8).AsUInt64();
		Vector128<ulong> k3k4 = Vector128.Create(0x00000000f20c0dfe, 0x000000014cd00bd6).AsUInt64();
		Vector128<ulong> k5 = Vector128.Create(0x00000000dd45aab8, 0x0000000000000000).AsUInt64();
		Vector128<ulong> ru = Vector128.Create(0x0000000105ec76f1, 0x00000000dea713f1).AsUInt64();
		Vector128<ulong> mask32 = Vector128.Create(0x00000000ffffffff, 0x0000000000000000).AsUInt64();
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateDefault(ReadOnlySpan<byte> source)
	{
		int length = source.Length;
		int offset = 0;
		ref byte sourceRef = ref source.GetReference();

		if (Sse42.X64.IsSupported || Crc32.Arm64.IsSupported)
		{
			while (length >= 8)
			{
				ref ulong data = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref sourceRef, offset));
				_state = BitOperations.Crc32C(_state, data);
				offset += 8;
				length -= 8;
			}
		}

		while (length >= 4)
		{
			ref uint data = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref sourceRef, offset));
			_state = BitOperations.Crc32C(_state, data);
			offset += 4;
			length -= 4;
		}

		if (length >= 2)
		{
			ref ushort data = ref Unsafe.As<byte, ushort>(ref Unsafe.Add(ref sourceRef, offset));
			_state = BitOperations.Crc32C(_state, data);
			offset += 2;
			length -= 2;
		}

		if (length > 0)
		{
			_state = BitOperations.Crc32C(_state, Unsafe.Add(ref sourceRef, offset));
		}
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
