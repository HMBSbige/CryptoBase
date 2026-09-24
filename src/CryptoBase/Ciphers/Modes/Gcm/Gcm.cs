namespace CryptoBase.Ciphers.Modes.Gcm;

internal static class Gcm
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Begin(ReadOnlySpan<byte> nonce, out Vector128<byte> j0)
	{
		Debug.Assert(nonce.Length is 12);
		ref byte source = ref nonce.GetReference();
		ulong low = Unsafe.ReadUnaligned<ulong>(ref source);
		ulong high = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 8));
		high = BitConverter.IsLittleEndian ? high | 0x0100000000000000UL : high << 32 | 1UL;
		j0 = Vector128.Create(low, high).AsByte();
		return j0.WithElement(15, (byte)2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> CreateLengthBlock(int associatedDataLength, int ciphertextLength)
	{
		ulong associatedDataBits = (ulong)associatedDataLength << 3;
		ulong ciphertextBits = (ulong)ciphertextLength << 3;

		if (BitConverter.IsLittleEndian)
		{
			associatedDataBits = BinaryPrimitives.ReverseEndianness(associatedDataBits);
			ciphertextBits = BinaryPrimitives.ReverseEndianness(ciphertextBits);
		}

		return Vector128.Create(associatedDataBits, ciphertextBits).AsByte();
	}
}
