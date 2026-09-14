using CryptoBase.Ciphers.Streams;

namespace CryptoBase.Tests.Ciphers.Streams;

public sealed record SnuffleCase(string Name, Func<SnuffleCipher> Create, ulong MaxCounter)
{
	public override string ToString()
	{
		return Name;
	}
}
