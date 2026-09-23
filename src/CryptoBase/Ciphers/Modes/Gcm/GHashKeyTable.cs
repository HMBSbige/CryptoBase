namespace CryptoBase.Ciphers.Modes.Gcm;

internal sealed class GHashKeyTable<T>(in T value) : IDisposable where T : unmanaged
{
	internal T Value = value;

	public void Dispose()
	{
		Value.ZeroMemory();
	}
}
