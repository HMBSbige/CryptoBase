namespace CryptoBase.Ciphers.Modes.Gcm;

// Each table is initialized in place to avoid copying the powers through the stack.
internal sealed class GHashKeyTable<T> : IDisposable where T : unmanaged
{
	internal T Value;

	public void Dispose()
	{
		Value.ZeroMemory();
	}
}
