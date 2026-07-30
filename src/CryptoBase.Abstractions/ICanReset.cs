namespace CryptoBase.Abstractions;

/// <summary>
/// Represents an object whose processing state can be reset.
/// </summary>
public interface ICanReset
{
	/// <summary>
	/// Resets the object's processing state.
	/// </summary>
	void Reset();
}
