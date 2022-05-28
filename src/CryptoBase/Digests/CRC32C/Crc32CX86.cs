using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Digests.CRC32C;

/// <summary>
/// Same as <see cref="Crc32X86"/> , but different constants.
/// Abstraction will cause performance issue!
/// WTF.NET
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

	public unsafe void Update(ReadOnlySpan<byte> source)
	{
		if (Sse2.IsSupported && Pclmulqdq.IsSupported && source.Length >= 64)
		{
			fixed (byte* p = source)
			{
				_state = Update(p, source.Length, _state);
				source = source[^(source.Length % 0x10)..];
			}
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
	private static unsafe uint Update(byte* buffer, int length, uint crc)
	{
		var x1 = Sse2.LoadVector128(buffer).AsUInt64();
		var x2 = Sse2.LoadVector128(buffer + 0x10).AsUInt64();
		var x3 = Sse2.LoadVector128(buffer + 0x20).AsUInt64();
		var x4 = Sse2.LoadVector128(buffer + 0x30).AsUInt64();
		var vCrc = Vector128.CreateScalar(crc).AsUInt64();
		x1 = Sse2.Xor(x1, vCrc);

		length -= 0x40;
		buffer += 0x40;

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

			x1 = Sse2.Xor(x1, Sse2.LoadVector128(buffer).AsUInt64());
			x2 = Sse2.Xor(x2, Sse2.LoadVector128(buffer + 0x10).AsUInt64());
			x3 = Sse2.Xor(x3, Sse2.LoadVector128(buffer + 0x20).AsUInt64());
			x4 = Sse2.Xor(x4, Sse2.LoadVector128(buffer + 0x30).AsUInt64());

			length -= 0x40;
			buffer += 0x40;
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
			x1 = Sse2.Xor(x1, Sse2.LoadVector128(buffer).AsUInt64());

			length -= 0x10;
			buffer += 0x10;
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateSse42(ReadOnlySpan<byte> source)
	{
		if (Sse42.X64.IsSupported)
		{
			while (source.Length >= 8)
			{
				var data = BinaryPrimitives.ReadUInt64LittleEndian(source);
				_state = (uint)Sse42.X64.Crc32(_state, data);
				source = source[8..];
			}

			if (source.Length >= 4)
			{
				var data = BinaryPrimitives.ReadUInt32LittleEndian(source);
				_state = Sse42.Crc32(_state, data);
				source = source[4..];
			}
		}
		else
		{
			while (source.Length >= 4)
			{
				var data = BinaryPrimitives.ReadUInt32LittleEndian(source);
				_state = Sse42.Crc32(_state, data);
				source = source[4..];
			}
		}

		if (source.Length >= 2)
		{
			var data = BinaryPrimitives.ReadUInt16LittleEndian(source);
			_state = Sse42.Crc32(_state, data);
			source = source[2..];
		}

		foreach (var b in source)
		{
			_state = Sse42.Crc32(_state, b);
		}
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
