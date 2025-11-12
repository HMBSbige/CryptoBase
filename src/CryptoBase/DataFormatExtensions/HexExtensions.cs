namespace CryptoBase.DataFormatExtensions;

public static class HexExtensions
{
	extension(Span<byte> bytes)
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

	/// <inheritdoc cref="Convert.FromHexString(string)" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static byte[] FromHex(this string hex)
	{
		return Convert.FromHexString(hex);
	}

	/// <inheritdoc cref="Convert.FromHexString(ReadOnlySpan{char})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static byte[] FromHex(this ReadOnlySpan<char> hex)
	{
		return Convert.FromHexString(hex);
	}
}
