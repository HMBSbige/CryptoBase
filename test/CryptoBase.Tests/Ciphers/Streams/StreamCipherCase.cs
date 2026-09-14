using CryptoBase.Abstractions.Ciphers;

namespace CryptoBase.Tests.Ciphers.Streams;

public sealed record StreamCipherCase(string Name, Func<IStreamCipher> Create)
{
	public override string ToString()
	{
		return Name;
	}
}
