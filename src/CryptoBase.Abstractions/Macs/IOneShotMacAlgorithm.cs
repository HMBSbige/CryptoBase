namespace CryptoBase.Abstractions.Macs;

/// <summary>
/// Defines a one-shot message authentication code algorithm.
/// </summary>
public interface IOneShotMacAlgorithm
{
	/// <summary>
	/// Gets the MAC length, in bytes.
	/// </summary>
	/// <remarks>The value must be positive and constant.</remarks>
	static abstract int MacLengthInBytes { get; }

	/// <summary>
	/// Computes the MAC of <paramref name="source" /> using <paramref name="key" />.
	/// </summary>
	/// <remarks>Implementations must erase temporary key material and state before returning or throwing. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="key">The key.</param>
	/// <param name="source">The data to authenticate.</param>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="MacLengthInBytes" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> is invalid, or <paramref name="destination" /> is too short.</exception>
	static abstract int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination);
}
