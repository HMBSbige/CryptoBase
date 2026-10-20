namespace CryptoBase.Tests.Wycheproof;

public enum WycheproofResult
{
	Valid,
	Invalid
}

public abstract record WycheproofTestVector
{
	public required int TcId { get; init; }

	// The key generation files have no flags.
	public string[] Flags { get; init; } = [];

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

// Decapsulation after key generation from a seed; ek is missing where the seed has the wrong length.
public sealed record MLKemTestVector(byte[] Seed, byte[] C, byte[] K, byte[]? Ek = null) : WycheproofTestVector;

public sealed record MLKemEncapsTestVector(byte[] Ek, byte[] M, byte[] C, byte[] K) : WycheproofTestVector;

public sealed record MLKemKeyGenTestVector(byte[] Seed, byte[] Ek, byte[] Dk) : WycheproofTestVector;

// Only the valid vectors have K.
public sealed record MLKemDecapsValidationTestVector(byte[] Dk, byte[] Ek, byte[] C, byte[]? K = null) : WycheproofTestVector;
