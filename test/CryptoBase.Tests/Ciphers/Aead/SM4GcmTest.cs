using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Tests.Ciphers.Blocks.SM4;
using CryptoBase.Tests.Ciphers.Modes;
using CryptoBase.Tests.Ciphers.Modes.Gcm;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

public class SM4GcmTest
{
	[Test]
	[MatrixDataSource]
	public async Task BatchBoundariesMatchScalarReference([Matrix(0, 1, 15, 16, 17, 1007, 1008, 1009, 1023, 1024, 1025, 2031, 2032, 2033, 2049, 3055, 3056, 3057, 4095, 4096, 4097, 8192, 8193)] int length)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] nonce = CreateDeterministicSource(12);
		byte[] associatedData = CreateDeterministicSource(17);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = EncryptReference(key, nonce, plaintext, associatedData);
		using GcmMode128<SM4Cipher> cipher = GcmMode128<SM4Cipher>.Create(key);
		byte[] source = CreateGuardedBuffer(3, length);
		plaintext.CopyTo(source, 3);
		byte[] destination = CreateGuardedBuffer(5, length);
		byte[] tag = CreateGuardedBuffer(7, 16);

		cipher.Encrypt(nonce, source.AsSpan(3, length), destination.AsSpan(5), tag.AsSpan(7, 16), associatedData);
		await AssertOutput(destination, 5, expected);
		await AssertOutput(tag, 7, expectedTag);
		await AssertOutput(source, 3, plaintext);
		await Assert.That(cipher.TryDecrypt(nonce, expected, expectedTag, destination.AsSpan(5), associatedData)).IsTrue();
		await AssertOutput(destination, 5, plaintext);

		cipher.Encrypt(nonce, destination.AsSpan(5, length), destination.AsSpan(5), tag.AsSpan(7, 16), associatedData);
		await AssertOutput(destination, 5, expected);
		await AssertOutput(tag, 7, expectedTag);
		await Assert.That(cipher.TryDecrypt(nonce, destination.AsSpan(5, length), expectedTag, destination.AsSpan(5), associatedData)).IsTrue();
		await AssertOutput(destination, 5, plaintext);

		expectedTag[0] ^= 1;
		PrepareDestination(destination);
		await Assert.That(cipher.TryDecrypt(nonce, expected, expectedTag, destination.AsSpan(5), associatedData)).IsFalse();
		await AssertOutput(destination, 5, new byte[length]);
		expected.CopyTo(destination, 5);
		await Assert.That(cipher.TryDecrypt(nonce, destination.AsSpan(5, length), expectedTag, destination.AsSpan(5), associatedData)).IsFalse();
		await AssertOutput(destination, 5, new byte[length]);
	}

	private static (byte[] Ciphertext, byte[] Tag) EncryptReference(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
	{
		byte[] ciphertext = CtrReference.Transform([.. nonce, 0, 0, 0, 2], plaintext, counters => SM4Reference.Transform(key, counters), 32);
		byte[] tagMask = SM4Reference.Transform(key, [.. nonce, 0, 0, 0, 1]);
		byte[] hashKey = SM4Reference.Transform(key, new byte[16]);
		byte[] lengths = new byte[16];
		BinaryPrimitives.WriteUInt64BigEndian(lengths, (ulong)associatedData.Length * 8);
		BinaryPrimitives.WriteUInt64BigEndian(lengths.AsSpan(8), (ulong)ciphertext.Length * 8);
		Vector128<byte> hash = GHashTest.ComputeReferenceHash(hashKey, associatedData, ciphertext, lengths);
		byte[] tag = hash.AsReadOnlySpan().ToArray();

		for (int i = 0; i < tag.Length; ++i)
		{
			tag[i] ^= tagMask[i];
		}

		return (ciphertext, tag);
	}
}
