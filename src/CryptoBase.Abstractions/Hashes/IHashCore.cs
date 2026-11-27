namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines a hash core.
/// </summary>
/// <typeparam name="TSelf">The implementing core type.</typeparam>
public interface IHashCore<TSelf> : IIncrementalHashCore where TSelf : unmanaged, IHashCore<TSelf>
{
	/// <summary>
	/// Initializes the supplied storage for a new hash computation.
	/// </summary>
	/// <remarks>Must not fail.</remarks>
	/// <param name="core">The storage in which to initialize the core.</param>
	static abstract void Initialize(out TSelf core);
}
