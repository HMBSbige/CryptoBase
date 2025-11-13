namespace CryptoBase.DataFormatExtensions;

public static class HexExtensions
{
	extension(ReadOnlySpan<byte> bytes)
	{
		/// <inheritdoc cref="Convert.ToHexStringLower(ReadOnlySpan{byte})" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public string ToHex()
		{
			return Convert.ToHexStringLower(bytes);
		}

		/// <inheritdoc cref="Convert.ToHexString(ReadOnlySpan{byte})" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public string ToHexString()
		{
			return Convert.ToHexString(bytes);
		}
	}

	extension(ReadOnlySpan<char> hexString)
	{
		/// <inheritdoc cref="Convert.FromHexString(ReadOnlySpan{char})" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public byte[] FromHex()
		{
			return Convert.FromHexString(hexString);
		}
	}
}
