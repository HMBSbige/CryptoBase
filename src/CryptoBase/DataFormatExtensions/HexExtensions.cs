namespace CryptoBase.DataFormatExtensions;

public static class HexExtensions
{
	/// <inheritdoc cref="Convert.ToHexStringLower(ReadOnlySpan{byte})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static string ToHex(this Span<byte> bytes)
	{
		return Convert.ToHexStringLower(bytes);
	}

	/// <inheritdoc cref="Convert.ToHexStringLower(ReadOnlySpan{byte})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static string ToHex(this ReadOnlySpan<byte> bytes)
	{
		return Convert.ToHexStringLower(bytes);
	}

	/// <inheritdoc cref="Convert.ToHexString(ReadOnlySpan{byte})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static string ToHexString(this Span<byte> bytes)
	{
		return Convert.ToHexString(bytes);
	}

	/// <inheritdoc cref="Convert.ToHexString(ReadOnlySpan{byte})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static string ToHexString(this ReadOnlySpan<byte> bytes)
	{
		return Convert.ToHexString(bytes);
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
