using CryptoBase.Kdf;

namespace CryptoBase.Tests.Kdf.Argon2;

[InheritsTests]
public class Argon2dTest() : Argon2DeriveKeyTest(Argon2Type.Argon2d)
{
	protected override void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination, Argon2Parameters parameters, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, int maxDegreeOfParallelism)
	{
		Argon2d.DeriveKey(password, salt, destination, parameters, secret, associatedData, maxDegreeOfParallelism);
	}
}
