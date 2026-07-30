namespace CryptoBase.Abstractions.Vectors;

/// <summary>A 16-byte buffer with overlapping scalar and SIMD views.</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
public struct VectorBuffer16
{
	/// <summary>The 128-bit byte-vector view of the entire buffer.</summary>
	[FieldOffset(0 * 16)] public Vector128<byte> V128;

	/// <summary>The unsigned 128-bit integer view of the entire buffer.</summary>
	[FieldOffset(0 * 16)] public UInt128 U128;
	/// <summary>The signed 128-bit integer view of the entire buffer.</summary>
	[FieldOffset(0 * 16)] public Int128 I128;

	/// <summary>The unsigned 64-bit integer view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 8)] public ulong Lower;
	/// <summary>The unsigned 64-bit integer view beginning at byte offset 8.</summary>
	[FieldOffset(1 * 8)] public ulong Upper;

	/// <summary>The unsigned 32-bit integer view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 4)] public uint U0;
	/// <summary>The unsigned 32-bit integer view beginning at byte offset 4.</summary>
	[FieldOffset(1 * 4)] public uint U1;
	/// <summary>The unsigned 32-bit integer view beginning at byte offset 8.</summary>
	[FieldOffset(2 * 4)] public uint U2;
	/// <summary>The unsigned 32-bit integer view beginning at byte offset 12.</summary>
	[FieldOffset(3 * 4)] public uint U3;

	/// <summary>Converts the buffer to a mutable byte-span view.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer16 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	/// <summary>Computes the bitwise exclusive OR of two buffers.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer16 operator ^(in VectorBuffer16 left, in VectorBuffer16 right)
	{
		if (Vector128.IsHardwareAccelerated)
		{
			return new VectorBuffer16 { V128 = left.V128 ^ right.V128 };
		}

		return new VectorBuffer16 { U128 = left.U128 ^ right.U128 };
	}
}
