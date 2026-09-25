namespace CryptoBase.Ciphers.Blocks.SM4;

internal static class SM4AesConstants
{
	internal static Vector128<byte> InverseShiftRows
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
	}
}
