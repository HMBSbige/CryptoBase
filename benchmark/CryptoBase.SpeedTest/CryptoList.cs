namespace CryptoBase.SpeedTest;

internal static class CryptoList
{
	public const string All = @"all";
	public const string Aes128Ctr = @"aes-128-ctr";
	public const string Aes192Ctr = @"aes-192-ctr";
	public const string Aes256Ctr = @"aes-256-ctr";
	public const string SM4Ctr = @"sm4-ctr";
	public const string ChaCha20Original = @"chacha20";
	public const string ChaCha20 = @"chacha20-ietf";
	public const string XChaCha20 = @"xchacha20";
	public const string Salsa20 = @"salsa20";
	public const string XSalsa20 = @"xsalsa20";

	public const string Aes128Gcm = @"aes-128-gcm";
	public const string Aes192Gcm = @"aes-192-gcm";
	public const string Aes256Gcm = @"aes-256-gcm";
	public const string SM4Gcm = @"sm4-gcm";
	public const string ChaCha20Poly1305 = @"chacha20-ietf-poly1305";
	public const string XChaCha20Poly1305 = @"xchacha20-ietf-poly1305";
	public const string Aes128Xts = @"aes-128-xts";
	public const string Aes256Xts = @"aes-256-xts";

	public static readonly ImmutableList<string> Methods =
	[
		Aes128Ctr,
		Aes192Ctr,
		Aes256Ctr,
		SM4Ctr,
		ChaCha20Original,
		ChaCha20,
		XChaCha20,
		Salsa20,
		XSalsa20,
		Aes128Gcm,
		Aes192Gcm,
		Aes256Gcm,
		SM4Gcm,
		ChaCha20Poly1305,
		XChaCha20Poly1305,
		Aes128Xts,
		Aes256Xts
	];

	public static void Run(string name, CryptoTest test)
	{
		ReadOnlySpan<byte> key32 = CryptoTest.Key.Slice(0, 32);
		ReadOnlySpan<byte> key24 = CryptoTest.Key.Slice(0, 24);
		ReadOnlySpan<byte> key16 = CryptoTest.Key.Slice(0, 16);
		ReadOnlySpan<byte> iv16 = CryptoTest.IV.Slice(0, 16);
		ReadOnlySpan<byte> iv24 = CryptoTest.IV.Slice(0, 24);

		switch (name)
		{
			case Aes128Ctr:
			{
				using CtrMode128<AesCipher> crypto = CtrMode128<AesCipher>.Create(key16, iv16);
				test.TestStream(crypto);
				break;
			}
			case Aes192Ctr:
			{
				using CtrMode128<AesCipher> crypto = CtrMode128<AesCipher>.Create(key24, iv16);
				test.TestStream(crypto);
				break;
			}
			case Aes256Ctr:
			{
				using CtrMode128<AesCipher> crypto = CtrMode128<AesCipher>.Create(key32, iv16);
				test.TestStream(crypto);
				break;
			}
			case SM4Ctr:
			{
				using CtrMode128<SM4Cipher> crypto = CtrMode128<SM4Cipher>.Create(key16, iv16);
				test.TestStream(crypto);
				break;
			}
			case ChaCha20Original:
			{
				using ChaCha20OriginalCipher crypto = new(key32, iv16.Slice(0, 8));
				test.TestStream(crypto);
				break;
			}
			case ChaCha20:
			{
				using ChaCha20Cipher crypto = new(key32, iv16.Slice(0, 12));
				test.TestStream(crypto);
				break;
			}
			case XChaCha20:
			{
				using XChaCha20Cipher crypto = new(key32, iv24);
				test.TestStream(crypto);
				break;
			}
			case Salsa20:
			{
				using Salsa20Cipher crypto = new(key32, iv16.Slice(0, 8));
				test.TestStream(crypto);
				break;
			}
			case XSalsa20:
			{
				using XSalsa20Cipher crypto = new(key32, iv24);
				test.TestStream(crypto);
				break;
			}
			case Aes128Gcm:
			{
				using GcmMode128<AesCipher> crypto = GcmMode128<AesCipher>.Create(key16);
				test.TestAead(crypto);
				break;
			}
			case Aes192Gcm:
			{
				using GcmMode128<AesCipher> crypto = GcmMode128<AesCipher>.Create(key24);
				test.TestAead(crypto);
				break;
			}
			case Aes256Gcm:
			{
				using GcmMode128<AesCipher> crypto = GcmMode128<AesCipher>.Create(key32);
				test.TestAead(crypto);
				break;
			}
			case SM4Gcm:
			{
				using GcmMode128<SM4Cipher> crypto = GcmMode128<SM4Cipher>.Create(key16);
				test.TestAead(crypto);
				break;
			}
			case ChaCha20Poly1305:
			{
				using ChaCha20Poly1305Cipher crypto = ChaCha20Poly1305Cipher.Create(key32);
				test.TestAead(crypto);
				break;
			}
			case XChaCha20Poly1305:
			{
				using XChaCha20Poly1305Cipher crypto = XChaCha20Poly1305Cipher.Create(key32);
				test.TestAead(crypto);
				break;
			}
			case Aes128Xts:
			{
				using XtsMode<AesCipher> crypto = XtsMode<AesCipher>.Create(key16, KeyForTweak.Slice(0, 16));
				test.TestDataUnit(crypto);
				break;
			}
			case Aes256Xts:
			{
				using XtsMode<AesCipher> crypto = XtsMode<AesCipher>.Create(key32, KeyForTweak);
				test.TestDataUnit(crypto);
				break;
			}
			default:
				throw new NotSupportedException(name);
		}
	}

	private static ReadOnlySpan<byte> KeyForTweak => "0123456789abcdef0123456789abcdef"u8;
}
