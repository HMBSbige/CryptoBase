using CryptoBase.Hpke;
using System.Reflection;

namespace CryptoBase.Tests.Hpke;

public class HpkeApiTest
{
	// Nk, Nn and Nt of RFC 9180, Section 7.3.
	[Test]
	[Arguments(HpkeAeadId.Aes128Gcm, 16, 12, 16)]
	[Arguments(HpkeAeadId.Aes256Gcm, 32, 12, 16)]
	[Arguments(HpkeAeadId.ChaCha20Poly1305, 32, 12, 16)]
	[Arguments(HpkeAeadId.ExportOnly, 0, 0, 0)]
	public async Task AeadSizesAreThoseOfTheRfc(HpkeAeadId aead, int keySize, int nonceSize, int tagSize)
	{
		await Assert.That((aead.KeySize, aead.NonceSize, aead.TagSize)).IsEqualTo((keySize, nonceSize, tagSize));
	}

	// Nh of RFC 9180, Section 7.2.
	[Test]
	[Arguments(HpkeKdfId.HkdfSha256, 32)]
	[Arguments(HpkeKdfId.HkdfSha384, 48)]
	[Arguments(HpkeKdfId.HkdfSha512, 64)]
	public async Task KdfHashLengthsAreThoseOfTheRfc(HpkeKdfId kdf, int hashLength)
	{
		await Assert.That(kdf.HashLength).IsEqualTo(hashLength);
	}

	[Test]
	public async Task UnsupportedValuesHaveNoSizes()
	{
		using (Assert.Multiple())
		{
			await Assert.That(static () => ((HpkeKdfId)0).HashLength).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("kdf");
			await Assert.That(static () => ((HpkeAeadId)0).KeySize).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("aead");
			await Assert.That(static () => ((HpkeAeadId)4).NonceSize).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("aead");
			await Assert.That(static () => ((HpkeAeadId)0xFFFE).TagSize).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("aead");
		}
	}

	// A sender context cannot open and a recipient context cannot seal or move its sender's sequence number.
	[Test]
	public async Task EachRoleHasOnlyItsOperations()
	{
		using (Assert.Multiple())
		{
			await Assert.That(PublicInstanceMethods<HpkeSenderContext>()).IsEquivalentTo(["Dispose", "Export", "Seal", "get_Aead", "get_Kdf", "get_SequenceNumber"]);
			await Assert.That(PublicInstanceMethods<HpkeRecipientContext>()).IsEquivalentTo(["Dispose", "Export", "TryOpen", "get_Aead", "get_Kdf", "get_SequenceNumber", "set_SequenceNumber"]);
		}
	}

	private static string[] PublicInstanceMethods<T>()
	{
		return [.. typeof(T).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly).Select(static method => method.Name)];
	}
}
