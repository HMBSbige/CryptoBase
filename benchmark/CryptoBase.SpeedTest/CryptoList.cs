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
	public const string Aes128Ccm = @"aes-128-ccm";
	public const string Aes192Ccm = @"aes-192-ccm";
	public const string Aes256Ccm = @"aes-256-ccm";
	public const string SM4Ccm = @"sm4-ccm";
	public const string Aes128Ccm8 = @"aes-128-ccm8";
	public const string Aes256Ccm8 = @"aes-256-ccm8";
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
		Aes128Ccm,
		Aes192Ccm,
		Aes256Ccm,
		SM4Ccm,
		Aes128Ccm8,
		Aes256Ccm8,
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
				test.TestStream(CtrMode128<AesCipher>.Create(key16, iv16));
				break;
			case Aes192Ctr:
				test.TestStream(CtrMode128<AesCipher>.Create(key24, iv16));
				break;
			case Aes256Ctr:
				test.TestStream(CtrMode128<AesCipher>.Create(key32, iv16));
				break;
			case SM4Ctr:
				test.TestStream(CtrMode128<SM4Cipher>.Create(key16, iv16));
				break;
			case ChaCha20Original:
				test.TestStream(new ChaCha20OriginalCipher(key32, iv16.Slice(0, 8)));
				break;
			case ChaCha20:
				test.TestStream(new ChaCha20Cipher(key32, iv16.Slice(0, 12)));
				break;
			case XChaCha20:
				test.TestStream(new XChaCha20Cipher(key32, iv24));
				break;
			case Salsa20:
				test.TestStream(new Salsa20Cipher(key32, iv16.Slice(0, 8)));
				break;
			case XSalsa20:
				test.TestStream(new XSalsa20Cipher(key32, iv24));
				break;
			case Aes128Gcm:
				test.TestAead(GcmMode<AesCipher>.Create(key16));
				break;
			case Aes192Gcm:
				test.TestAead(GcmMode<AesCipher>.Create(key24));
				break;
			case Aes256Gcm:
				test.TestAead(GcmMode<AesCipher>.Create(key32));
				break;
			case SM4Gcm:
				test.TestAead(GcmMode<SM4Cipher>.Create(key16));
				break;
			case Aes128Ccm:
				test.TestAead(CcmMode<AesCipher>.Create(key16));
				break;
			case Aes192Ccm:
				test.TestAead(CcmMode<AesCipher>.Create(key24));
				break;
			case Aes256Ccm:
				test.TestAead(CcmMode<AesCipher>.Create(key32));
				break;
			case SM4Ccm:
				test.TestAead(CcmMode<SM4Cipher>.Create(key16));
				break;
			case Aes128Ccm8:
				test.TestAead(Ccm8Mode<AesCipher>.Create(key16));
				break;
			case Aes256Ccm8:
				test.TestAead(Ccm8Mode<AesCipher>.Create(key32));
				break;
			case ChaCha20Poly1305:
				test.TestAead(ChaCha20Poly1305Cipher.Create(key32));
				break;
			case XChaCha20Poly1305:
				test.TestAead(XChaCha20Poly1305Cipher.Create(key32));
				break;
			case Aes128Xts:
				test.TestDataUnit(XtsMode<AesCipher>.Create(key16, KeyForTweak.Slice(0, 16)));
				break;
			case Aes256Xts:
				test.TestDataUnit(XtsMode<AesCipher>.Create(key32, KeyForTweak));
				break;
			default:
				throw new NotSupportedException(name);
		}
	}

	private static ReadOnlySpan<byte> KeyForTweak => "0123456789abcdef0123456789abcdef"u8;
}
