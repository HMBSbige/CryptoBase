using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Modes;

public class AesCtrXtsOracleTest
{
	private const int FragmentedPrefixLength = 8193;
	private const int ContinuationLength = 145;

	// The triangular sums for chunks 0..15 visit every residual index modulo 16.
	private static readonly int[] FragmentChunks = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 17, 63, 64, 65, 127, 128, 129, 2047, 2048, 2049];

	public static IEnumerable<int> XtsLengths()
	{
		int[] blockAligned = [16, 32, 48, 64, 96, 112, 128, 192, 224, 240, 256, 4097];
		IEnumerable<int> stealing = from ordinaryLength in new[] { 0, 64, 128 } from tail in Enumerable.Range(1, 15) select ordinaryLength + 16 + tail;
		return blockAligned.Union(stealing).Order();
	}

	[Test]
	[MatrixDataSource]
	public async Task CtrBoundariesMatchBclOracle([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 31, 32, 33, 48, 49, 63, 64, 65, 80, 96, 112, 127, 128, 129, 144, 160, 192, 224, 240, 256, 4097)] int length)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] counter = CreateDeterministicSource(16);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] expected = CtrOracle(key, counter, plaintext);

		byte[] source = WithGuards(plaintext, 3);
		byte[] destination = CreateGuardedBuffer(5, length);

		using (CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, counter))
		{
			cipher.Xor(source.AsSpan(3, length), destination.AsSpan(5));
		}

		await VerifyOutput(destination, 5, expected, "encryption");
		await VerifyOutput(source, 3, plaintext, "source unchanged");

		byte[] inPlace = WithGuards(plaintext, 7);

		using (CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, counter))
		{
			cipher.Xor(inPlace.AsSpan(7, length), inPlace.AsSpan(7));
		}

		await VerifyOutput(inPlace, 7, expected, "in-place encryption");
	}

	[Test]
	[MatrixDataSource]
	public async Task CtrBulkContinuationMatchesBclOracle([Matrix(16, 24, 32)] int keyLength, [Matrix("000102030405060708090A0B0C0D0E0F", "000102030405060708090A0BFFFFFFFD", "0001020304050607FFFFFFFFFFFFFFFD", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD")] string counterHex)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] counter = Convert.FromHexString(counterHex);
		byte[] plaintext = CreateDeterministicSource(FragmentedPrefixLength + ContinuationLength);
		byte[] expected = CtrOracle(key, counter, plaintext);
		byte[] buffer = CreateGuardedBuffer(5, plaintext.Length);

		using (CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, counter))
		{
			cipher.Xor(plaintext.AsSpan(0, FragmentedPrefixLength), buffer.AsSpan(5, FragmentedPrefixLength));
			cipher.Xor(plaintext.AsSpan(FragmentedPrefixLength), buffer.AsSpan(5 + FragmentedPrefixLength));
		}

		await VerifyOutput(buffer, 5, expected, "bulk continuation");
	}

	[Test]
	[MatrixDataSource]
	public async Task CtrFragmentedResidualKeystreamMatchesBclOracle([Matrix(16, 24, 32)] int keyLength, [Matrix("000102030405060708090A0B0C0D0E0F", "000102030405060708090A0BFFFFFFFD", "0001020304050607FFFFFFFFFFFFFFFD", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD")] string counterHex, [Matrix] bool inPlace)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] counter = Convert.FromHexString(counterHex);
		byte[] plaintext = CreateDeterministicSource(FragmentedPrefixLength + ContinuationLength);
		byte[] expected = CtrOracle(key, counter, plaintext);
		byte[] buffer = WithGuards(inPlace ? plaintext : new byte[plaintext.Length], 3);

		using (CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, counter))
		{
			Span<byte> output = buffer.AsSpan(3, plaintext.Length);
			XorFragmented(cipher, inPlace ? output : plaintext, output);
		}

		await VerifyOutput(buffer, 3, expected, "fragmented");
	}

	[Test]
	[Arguments(1)]
	[Arguments(15)]
	[Arguments(129)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task CtrRejectsBeforeWritingOrAdvancingState(int consumed)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] counter = CreateDeterministicSource(16);
		byte[] plaintext = CreateDeterministicSource(consumed + 4097);
		byte[] expected = CtrOracle(key, counter, plaintext);
		byte[] destination = CreateGuardedBuffer(1, 4097);
		using CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, counter);
		cipher.Xor(plaintext.AsSpan(0, consumed), new byte[consumed]);

		await Assert.That(() => cipher.Xor(plaintext.AsSpan(consumed), destination.AsSpan(1, 4096))).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel).Because("short destination");

		foreach ((int sourceOffset, int destinationOffset) in new[] { (0, 1), (1, 0) })
		{
			byte[] overlap = CreateDeterministicSource(4098);
			byte[] original = overlap.ToArray();
			await Assert.That(() => cipher.Xor(overlap.AsSpan(sourceOffset, 4097), overlap.AsSpan(destinationOffset, 4097))).ThrowsExactly<ArgumentException>();
			await Assert.That(overlap).IsEquivalentTo(original, CollectionOrdering.Matching).Because($"overlap source={sourceOffset}, destination={destinationOffset}");
		}

		cipher.Xor(plaintext.AsSpan(consumed), destination.AsSpan(1));
		await VerifyOutput(destination, 1, expected.AsSpan(consumed).ToArray(), "continuation after rejection");
	}

	[Test]
	[MatrixDataSource]
	public async Task XtsBoundariesAndStealingMatchBclOracle([Matrix(16, 24, 32)] int keyLength, [MatrixMethod<AesCtrXtsOracleTest>(nameof(XtsLengths))] int length)
	{
		using XtsFixture xts = new(keyLength);
		byte[] iv = xts.IvForEncryptedTweak(Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
		await VerifyXtsRoundTrip(xts, iv, length);
	}

	[Test]
	[MatrixDataSource]
	public async Task XtsTweakValuesMatchBclOracle([Matrix(16, 24, 32)] int keyLength, [Matrix("00000000000000000000000000000000", "179A1DA023A629AC2FB235B83BBE41C4")] string encryptedTweakHex)
	{
		using XtsFixture xts = new(keyLength);
		byte[] iv = xts.IvForEncryptedTweak(Convert.FromHexString(encryptedTweakHex));
		await VerifyXtsRoundTrip(xts, iv, 4097);
	}

	[Test]
	[MatrixDataSource]
	public async Task XtsConsumesAliasedIvBeforeWriting([Matrix(17, 145)] int length, [Matrix] bool ivAtEnd, [Matrix] bool decrypt)
	{
		using XtsFixture xts = new(16);
		byte[] input = CreateDeterministicSource(length);
		int ivOffset = ivAtEnd ? length - 16 : 0;
		byte[] iv = input.AsSpan(ivOffset, 16).ToArray();
		byte[] expected = xts.Oracle(iv, input, decrypt);

		byte[] inPlace = WithGuards(input, 3);
		xts.Transform(decrypt, inPlace.AsSpan(3 + ivOffset, 16), inPlace.AsSpan(3, length), inPlace.AsSpan(3));
		await VerifyOutput(inPlace, 3, expected, "IV aliases in-place buffer");

		byte[] destinationAlias = CreateGuardedBuffer(5, length);
		iv.CopyTo(destinationAlias, 5 + ivOffset);
		xts.Transform(decrypt, destinationAlias.AsSpan(5 + ivOffset, 16), input, destinationAlias.AsSpan(5));
		await VerifyOutput(destinationAlias, 5, expected, "IV aliases destination");
	}

	private static async Task VerifyXtsRoundTrip(XtsFixture xts, byte[] iv, int length)
	{
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] expected = xts.Oracle(iv, plaintext, false);
		byte[] unalignedIv = WithGuards(iv, 1);
		ReadOnlySpan<byte> ivSpan = unalignedIv.AsSpan(1, 16);
		byte[] source = WithGuards(plaintext, 3);
		byte[] ciphertext = WithGuards(expected, 3);
		byte[] encrypted = CreateGuardedBuffer(5, length);
		byte[] decrypted = CreateGuardedBuffer(5, length);
		byte[] inPlaceEncrypted = WithGuards(plaintext, 7);

		xts.Transform(false, ivSpan, source.AsSpan(3, length), encrypted.AsSpan(5));
		xts.Transform(true, ivSpan, ciphertext.AsSpan(3, length), decrypted.AsSpan(5));
		xts.Transform(false, ivSpan, inPlaceEncrypted.AsSpan(7, length), inPlaceEncrypted.AsSpan(7));
		byte[] inPlaceDecrypted = inPlaceEncrypted.ToArray();
		xts.Transform(true, ivSpan, inPlaceDecrypted.AsSpan(7, length), inPlaceDecrypted.AsSpan(7));

		await VerifyOutput(encrypted, 5, expected, "encryption");
		await VerifyOutput(source, 3, plaintext, "source unchanged");
		await VerifyOutput(decrypted, 5, plaintext, "decryption");
		await VerifyOutput(ciphertext, 3, expected, "ciphertext unchanged");
		await VerifyOutput(inPlaceEncrypted, 7, expected, "in-place encryption");
		await VerifyOutput(inPlaceDecrypted, 7, plaintext, "in-place decryption");
		await VerifyOutput(unalignedIv, 1, iv, "IV unchanged");
	}

	private static void XorFragmented(CtrMode128<AesCipher> cipher, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;

		for (int chunkIndex = 0; offset < FragmentedPrefixLength; ++chunkIndex)
		{
			int length = Math.Min(FragmentChunks[chunkIndex % FragmentChunks.Length], FragmentedPrefixLength - offset);
			cipher.Xor(source.Slice(offset, length), destination.Slice(offset, length));
			offset += length;
		}

		cipher.Xor([], destination.Slice(offset));
		cipher.Xor(source.Slice(offset), destination.Slice(offset));
	}

	private static byte[] CtrOracle(byte[] key, byte[] initialCounter, byte[] source)
	{
		return CtrReference.Transform(initialCounter, source, counters =>
		{
			using BclAes cipher = CreateBclCipher(key);
			return cipher.EncryptEcb(counters, PaddingMode.None);
		});
	}

	private static BclAes CreateBclCipher(ReadOnlySpan<byte> key)
	{
		BclAes cipher = BclAes.Create();
		cipher.Key = key.ToArray();
		return cipher;
	}

	private static byte[] WithGuards(byte[] payload, int offset)
	{
		byte[] buffer = CreateGuardedBuffer(offset, payload.Length);
		payload.CopyTo(buffer, offset);
		return buffer;
	}

	private static async Task VerifyOutput(byte[] buffer, int offset, byte[] expected, string step)
	{
		await Assert.That(buffer.AsMemory(offset, expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching).Because(step);
		await Assert.That(buffer.AsMemory(0, offset)).All(static value => value is DestinationSentinel).Because(step + ", prefix guard");
		await Assert.That(buffer.AsMemory(offset + expected.Length)).All(static value => value is DestinationSentinel).Because(step + ", suffix guard");
	}

	private sealed class XtsFixture : IDisposable
	{
		private readonly BclAes _dataCipher;
		private readonly BclAes _tweakCipher;
		private readonly XtsMode<AesCipher> _cipher;

		public XtsFixture(int keyLength)
		{
			byte[] key = CreateDeterministicSource(keyLength * 2);
			ReadOnlySpan<byte> dataKey = key.AsSpan(0, keyLength);
			ReadOnlySpan<byte> tweakKey = key.AsSpan(keyLength);
			_dataCipher = CreateBclCipher(dataKey);
			_tweakCipher = CreateBclCipher(tweakKey);
			_cipher = XtsMode<AesCipher>.Create(dataKey, tweakKey);
		}

		public byte[] IvForEncryptedTweak(byte[] encryptedTweak)
		{
			return _tweakCipher.DecryptEcb(encryptedTweak, PaddingMode.None);
		}

		public void Transform(bool decrypt, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (decrypt)
			{
				_cipher.Decrypt(iv, source, destination);
			}
			else
			{
				_cipher.Encrypt(iv, source, destination);
			}
		}

		public byte[] Oracle(byte[] iv, byte[] source, bool decrypt)
		{
			UInt128 tweak = BinaryPrimitives.ReadUInt128LittleEndian(_tweakCipher.EncryptEcb(iv, PaddingMode.None));
			byte[] output = new byte[source.Length];
			int tail = source.Length % 16;
			int ordinaryLength = tail is 0 ? source.Length : source.Length - tail - 16;
			int offset = 0;

			for (; offset < ordinaryLength; offset += 16, tweak = MultiplyByAlpha(tweak))
			{
				XexBlock(tweak, source.AsSpan(offset, 16), output.AsSpan(offset, 16), decrypt);
			}

			if (tail is not 0)
			{
				UInt128 nextTweak = MultiplyByAlpha(tweak);
				Span<byte> complete = stackalloc byte[16];
				// CTS first recovers/produces the stolen block, then reconstructs its full input.
				XexBlock(decrypt ? nextTweak : tweak, source.AsSpan(offset, 16), complete, decrypt);
				complete.Slice(0, tail).CopyTo(output.AsSpan(offset + 16));
				source.AsSpan(offset + 16).CopyTo(complete);
				XexBlock(decrypt ? tweak : nextTweak, complete, output.AsSpan(offset, 16), decrypt);
			}

			return output;
		}

		public void Dispose()
		{
			_cipher.Dispose();
			_tweakCipher.Dispose();
			_dataCipher.Dispose();
		}

		private void XexBlock(UInt128 tweak, ReadOnlySpan<byte> source, Span<byte> destination, bool decrypt)
		{
			Span<byte> block = stackalloc byte[16];
			BinaryPrimitives.WriteUInt128LittleEndian(block, BinaryPrimitives.ReadUInt128LittleEndian(source) ^ tweak);

			if (decrypt)
			{
				_dataCipher.DecryptEcb(block, destination, PaddingMode.None);
			}
			else
			{
				_dataCipher.EncryptEcb(block, destination, PaddingMode.None);
			}

			BinaryPrimitives.WriteUInt128LittleEndian(destination, BinaryPrimitives.ReadUInt128LittleEndian(destination) ^ tweak);
		}

		private static UInt128 MultiplyByAlpha(UInt128 value)
		{
			return value << 1 ^ (value >> 127) * 0x87u;
		}
	}
}
