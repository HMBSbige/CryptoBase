namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines a hash core.
/// </summary>
/// <typeparam name="TSelf">The implementing core type.</typeparam>
public interface IHashCore<out TSelf> : IIncrementalHashCore where TSelf : unmanaged, IHashCore<TSelf>
{
	/// <summary>
	/// Creates an initialized core.
	/// </summary>
	/// <remarks>Must not fail.</remarks>
	/// <returns>The initialized core.</returns>
	static abstract TSelf Create();
}
