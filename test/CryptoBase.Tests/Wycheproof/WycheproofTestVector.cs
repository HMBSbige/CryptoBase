namespace CryptoBase.Tests.Wycheproof;

public enum WycheproofResult
{
	Valid,
	Invalid
}

public abstract record WycheproofTestVector
{
	public required int TcId { get; init; }

	public required string[] Flags { get; init; }

	public required WycheproofResult Result { get; init; }

	public sealed override string ToString()
	{
		return Flags is [] ? $"tcId {TcId}" : $"tcId {TcId}: {string.Join(", ", Flags)}";
	}
}

public sealed record AeadTestVector(byte[] Key, byte[] Iv, byte[] Aad, byte[] Msg, byte[] Ct, byte[] Tag) : WycheproofTestVector;

public sealed record IndCpaTestVector(byte[] Key, byte[] Iv, byte[] Msg, byte[] Ct) : WycheproofTestVector;

public sealed record MacTestVector(byte[] Key, byte[] Msg, byte[] Tag) : WycheproofTestVector;

public sealed record HkdfTestVector(byte[] Ikm, byte[] Salt, byte[] Info, int Size, byte[] Okm) : WycheproofTestVector;
