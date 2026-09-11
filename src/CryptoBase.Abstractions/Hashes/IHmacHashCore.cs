namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines a hash core usable with HMAC.
/// </summary>
/// <typeparam name="TSelf">The implementing core type.</typeparam>
public interface IHmacHashCore<out TSelf> : IHashCore<TSelf> where TSelf : unmanaged, IHmacHashCore<TSelf>
{
	/// <summary>
	/// Gets the HMAC input block size, in bytes.
	/// </summary>
	/// <remarks>Must be at least <see cref="IIncrementalHashCore.HashLengthInBytes" />.</remarks>
	static abstract int HmacBlockSizeInBytes { get; }
}
