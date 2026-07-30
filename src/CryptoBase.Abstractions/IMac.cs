namespace CryptoBase.Abstractions;

/// <summary>
/// Represents a stateful message authentication code computation.
/// </summary>
public interface IMac : IDisposable, ICanReset
{
	/// <summary>
	/// Gets the algorithm name.
	/// </summary>
	string Name { get; }

	/// <summary>
	/// Gets the authentication code length, in bytes.
	/// </summary>
	int Length { get; }

	/// <summary>
	/// Processes the supplied data as one input segment.
	/// </summary>
	void Update(scoped ReadOnlySpan<byte> source);

	/// <summary>
	/// Writes the authentication code and resets the state.
	/// </summary>
	void GetMac(scoped Span<byte> destination);
}
