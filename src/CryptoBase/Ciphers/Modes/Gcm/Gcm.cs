namespace CryptoBase.Ciphers.Modes.Gcm;

internal static class Gcm
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Begin(ReadOnlySpan<byte> nonce, out Vector128<byte> j0)
	{
		Debug.Assert(nonce.Length is 12);
		ref byte source = ref MemoryMarshal.GetReference(nonce);
		ulong low = Unsafe.ReadUnaligned<ulong>(ref source);
		ulong high = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 8)) | 0x0100000000000000UL;
		j0 = Vector128.CreateUInt64(low, high).AsByte();
		return j0.WithElement(15, (byte)2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> CreateLengthBlock(int associatedDataLength, int ciphertextLength)
	{
		ulong associatedDataBits = BinaryPrimitives.ReverseEndianness((ulong)associatedDataLength << 3);
		ulong ciphertextBits = BinaryPrimitives.ReverseEndianness((ulong)ciphertextLength << 3);
		return Vector128.CreateUInt64(associatedDataBits, ciphertextBits).AsByte();
	}
}
