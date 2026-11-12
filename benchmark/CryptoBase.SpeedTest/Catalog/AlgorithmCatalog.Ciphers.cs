using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Streams;
using CryptoBase.Platform;

namespace CryptoBase.SpeedTest.Catalog;

internal static partial class AlgorithmCatalog
{
	// CCM with a 12-byte nonce has a 3-byte length field.
	private const int CcmMaximumInputSize = (1 << 24) - 1;

	private static AlgorithmEntry[] CreateStreamEntries()
	{
		return
		[
			Stream("aes-128-ctr", static () => CtrMode128<AesCipher>.Create(Key(16), Iv(16))),
			Stream("aes-192-ctr", static () => CtrMode128<AesCipher>.Create(Key(24), Iv(16))),
			Stream("aes-256-ctr", static () => CtrMode128<AesCipher>.Create(Key(32), Iv(16))),
			Stream("sm4-ctr", static () => CtrMode128<SM4Cipher>.Create(Key(16), Iv(16))),
			Stream("chacha20", static () => new ChaCha20OriginalCipher(Key(32), Iv(ChaCha20OriginalCipher.IVSize))),
			Stream("chacha20-ietf", static () => new ChaCha20Cipher(Key(32), Iv(ChaCha20Cipher.IVSize))),
			Stream("xchacha20", static () => new XChaCha20Cipher(Key(32), Iv(XChaCha20Cipher.IVSize))),
			Stream("salsa20", static () => new Salsa20Cipher(Key(32), Iv(Salsa20Cipher.IVSize))),
			Stream("xsalsa20", static () => new XSalsa20Cipher(Key(32), Iv(XSalsa20Cipher.IVSize)))
		];
	}

	private static AlgorithmEntry[] CreateBlockEntries()
	{
		return
		[
			Block<AesCipher>("aes-128-ecb", keySize: 16),
			Block<AesCipher>("aes-192-ecb", keySize: 24),
			Block<AesCipher>("aes-256-ecb", keySize: 32),
			Block<SM4Cipher>("sm4-ecb", keySize: 16)
		];
	}

	private static AlgorithmEntry[] CreateAeadEntries()
	{
		return
		[
			Aead<GcmMode<AesCipher>>("aes-128-gcm", keySize: 16),
			Aead<GcmMode<AesCipher>>("aes-192-gcm", keySize: 24),
			Aead<GcmMode<AesCipher>>("aes-256-gcm", keySize: 32),
			Aead<GcmMode<SM4Cipher>>("sm4-gcm", keySize: 16),
			Aead<PlatformAesGcm>("platform-aes-128-gcm", keySize: 16),
			Aead<PlatformAesGcm>("platform-aes-256-gcm", keySize: 32),
			Aead<CcmMode<AesCipher>>("aes-128-ccm", keySize: 16, CcmMaximumInputSize),
			Aead<CcmMode<AesCipher>>("aes-192-ccm", keySize: 24, CcmMaximumInputSize),
			Aead<CcmMode<AesCipher>>("aes-256-ccm", keySize: 32, CcmMaximumInputSize),
			Aead<CcmMode<SM4Cipher>>("sm4-ccm", keySize: 16, CcmMaximumInputSize),
			Aead<Ccm8Mode<AesCipher>>("aes-128-ccm8", keySize: 16, CcmMaximumInputSize),
			Aead<Ccm8Mode<AesCipher>>("aes-256-ccm8", keySize: 32, CcmMaximumInputSize),
			Aead<ChaCha20Poly1305Cipher>("chacha20-ietf-poly1305", keySize: 32),
			Aead<XChaCha20Poly1305Cipher>("xchacha20-ietf-poly1305", keySize: 32),
			ChunkedMessage<Cobblestone128Cipher>("cobblestone-128", Cobblestone128Cipher.Encrypt, Cobblestone128Cipher.TryDecrypt),
			ChunkedMessage<Cobblestone256Cipher>("cobblestone-256", Cobblestone256Cipher.Encrypt, Cobblestone256Cipher.TryDecrypt)
		];
	}

	private static AlgorithmEntry[] CreateXtsEntries()
	{
		// XTS takes the data key and the tweak key concatenated, and needs at least one block.
		return
		[
			DataUnit<XtsMode<AesCipher>>("aes-128-xts", keySize: 32, minimumInputSize: 16),
			DataUnit<XtsMode<AesCipher>>("aes-256-xts", keySize: 64, minimumInputSize: 16)
		];
	}

	private static byte[] Key(int length)
	{
		return TestData.Sequence(length);
	}

	private static byte[] Iv(int length)
	{
		return TestData.Sequence(length);
	}
}
