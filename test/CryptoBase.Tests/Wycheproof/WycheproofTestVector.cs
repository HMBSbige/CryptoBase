using System.Text.Json.Serialization;

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

// A group that holds what its tests share, such as a key; Complete copies that into a test.
public abstract record WycheproofTestGroup<T> where T : WycheproofTestVector
{
	public required T[] Tests { get; init; }

	public abstract T Complete(T test);
}

public sealed record AeadTestVector(byte[] Key, byte[] Iv, byte[] Aad, byte[] Msg, byte[] Ct, byte[] Tag) : WycheproofTestVector;

public sealed record IndCpaTestVector(byte[] Key, byte[] Iv, byte[] Msg, byte[] Ct) : WycheproofTestVector;

public sealed record MacTestVector(byte[] Key, byte[] Msg, byte[] Tag) : WycheproofTestVector;

// KMAC encodes the output length L into its input, so the group's tag size, in bits, is the length the tag is computed for.
public sealed record KmacTestVector(byte[] Key, byte[] Msg, byte[] Tag) : WycheproofTestVector
{
	[JsonIgnore]
	public int TagSize { get; init; }
}

public sealed record KmacTestGroup(int TagSize) : WycheproofTestGroup<KmacTestVector>
{
	public override KmacTestVector Complete(KmacTestVector test)
	{
		return test with { TagSize = TagSize };
	}
}

public sealed record HkdfTestVector(byte[] Ikm, byte[] Salt, byte[] Info, int Size, byte[] Okm) : WycheproofTestVector;

// Decapsulation after key generation from a seed; ek is missing where the seed has the wrong length.
public sealed record MLKemTestVector(byte[] Seed, byte[] C, byte[] K, byte[]? Ek = null) : WycheproofTestVector;

public sealed record MLKemEncapsTestVector(byte[] Ek, byte[] M, byte[] C, byte[] K) : WycheproofTestVector;

public sealed record MLKemKeyGenTestVector(byte[] Seed, byte[] Ek, byte[] Dk) : WycheproofTestVector;

// Only the valid vectors have K.
public sealed record MLKemDecapsValidationTestVector(byte[] Dk, byte[] Ek, byte[] C, byte[]? K = null) : WycheproofTestVector;

public sealed record MLDsaVerifyTestVector(byte[] Msg, byte[] Sig, byte[]? Ctx = null) : WycheproofTestVector
{
	[JsonIgnore]
	public byte[] PublicKey { get; init; } = [];

	[JsonIgnore]
	public byte[] PublicKeyDer { get; init; } = [];
}

public sealed record MLDsaVerifyTestGroup(byte[] PublicKey, byte[] PublicKeyDer) : WycheproofTestGroup<MLDsaVerifyTestVector>
{
	public override MLDsaVerifyTestVector Complete(MLDsaVerifyTestVector test)
	{
		return test with { PublicKey = PublicKey, PublicKeyDer = PublicKeyDer };
	}
}

// The Internal vectors sign μ and have no message; the invalid ones have no μ and an empty signature. rnd is zero unless given.
public sealed record MLDsaSignTestVector(byte[] Sig, byte[]? Msg = null, byte[]? Mu = null, byte[]? Ctx = null, byte[]? Rnd = null) : WycheproofTestVector
{
	// The group has the seed or the private key, by file.
	[JsonIgnore]
	public byte[]? PrivateSeed { get; init; }

	[JsonIgnore]
	public byte[]? PrivateKey { get; init; }

	// Missing or empty in some groups.
	[JsonIgnore]
	public byte[]? PrivateKeyPkcs8 { get; init; }

	// Missing where the private key has the wrong length.
	[JsonIgnore]
	public byte[]? PublicKey { get; init; }
}

public sealed record MLDsaSignSeedTestGroup(byte[] PrivateSeed, byte[]? PublicKey = null, byte[]? PrivateKeyPkcs8 = null) : WycheproofTestGroup<MLDsaSignTestVector>
{
	public override MLDsaSignTestVector Complete(MLDsaSignTestVector test)
	{
		return test with { PrivateSeed = PrivateSeed, PublicKey = PublicKey, PrivateKeyPkcs8 = PrivateKeyPkcs8 };
	}
}

public sealed record MLDsaSignNoSeedTestGroup(byte[] PrivateKey, byte[]? PublicKey = null) : WycheproofTestGroup<MLDsaSignTestVector>
{
	public override MLDsaSignTestVector Complete(MLDsaSignTestVector test)
	{
		return test with { PrivateKey = PrivateKey, PublicKey = PublicKey };
	}
}
