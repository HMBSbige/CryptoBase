namespace CryptoBase.SpeedTest;

internal static class CryptoList
{
	public const string All = @"all";
	public const string Aes128Ctr = @"aes-128-ctr";
	public const string Aes192Ctr = @"aes-192-ctr";
	public const string Aes256Ctr = @"aes-256-ctr";
	public const string Aes128Cfb = @"aes-128-cfb";
	public const string Aes192Cfb = @"aes-192-cfb";
	public const string Aes256Cfb = @"aes-256-cfb";
	public const string Sm4Ctr = @"sm4-ctr";
	public const string Sm4Cfb = @"sm4-cfb";
	public const string Rc4 = @"rc4";
	public const string ChaCha20Original = @"chacha20";
	public const string ChaCha20 = @"chacha20-ietf";
	public const string XChaCha20 = @"xchacha20";
	public const string Salsa20 = @"salsa20";
	public const string XSalsa20 = @"xsalsa20";

	public const string Aes128Gcm = @"aes-128-gcm";
	public const string Aes192Gcm = @"aes-192-gcm";
	public const string Aes256Gcm = @"aes-256-gcm";
	public const string Sm4Gcm = @"sm4-gcm";
	public const string ChaCha20Poly1305 = @"chacha20-ietf-poly1305";
	public const string XChaCha20Poly1305 = @"xchacha20-ietf-poly1305";

	public static readonly ImmutableList<string> Methods =
	[
		Aes128Ctr,
		Aes192Ctr,
		Aes256Ctr,
		Aes128Cfb,
		Aes192Cfb,
		Aes256Cfb,
		Sm4Ctr,
		Sm4Cfb,
		Rc4,
		ChaCha20Original,
		ChaCha20,
		XChaCha20,
		Salsa20,
		XSalsa20,
		Aes128Gcm,
		Aes192Gcm,
		Aes256Gcm,
		Sm4Gcm,
		ChaCha20Poly1305,
		XChaCha20Poly1305
	];

	public static ISymmetricCrypto? GetSymmetricCrypto(string name)
	{
		ReadOnlySpan<byte> key32 = CryptoTest.Key.Slice(0, 32);
		ReadOnlySpan<byte> key24 = CryptoTest.Key.Slice(0, 24);
		ReadOnlySpan<byte> key16 = CryptoTest.Key.Slice(0, 16);
		ReadOnlySpan<byte> iv16 = CryptoTest.IV.Slice(0, 16);
		ReadOnlySpan<byte> iv24 = CryptoTest.IV.Slice(0, 24);

		return name switch
		{
			Aes128Ctr => StreamCryptoCreate.AesCtr(key16, iv16),
			Aes192Ctr => StreamCryptoCreate.AesCtr(key24, iv16),
			Aes256Ctr => StreamCryptoCreate.AesCtr(key32, iv16),
			Aes128Cfb => StreamCryptoCreate.AesCfb(true, key16, iv16),
			Aes192Cfb => StreamCryptoCreate.AesCfb(true, key24, iv16),
			Aes256Cfb => StreamCryptoCreate.AesCfb(true, key32, iv16),
			Sm4Ctr => StreamCryptoCreate.Sm4Ctr(key16, iv16),
			Sm4Cfb => StreamCryptoCreate.Sm4Cfb(true, key16, iv16),
			Rc4 => new RC4Crypto(key16),
			ChaCha20Original => new ChaCha20OriginalCrypto(key32, iv16),
			ChaCha20 => new ChaCha20Crypto(key32, iv16),
			XChaCha20 => new XChaCha20Crypto(key32, iv24),
			Salsa20 => new Salsa20Crypto(key32, iv16),
			XSalsa20 => new XSalsa20Crypto(key32, iv24),
			Aes128Gcm => AEADCryptoCreate.AesGcm(key16),
			Aes192Gcm => AEADCryptoCreate.AesGcm(key24),
			Aes256Gcm => AEADCryptoCreate.AesGcm(key32),
			Sm4Gcm => AEADCryptoCreate.Sm4Gcm(key16),
			ChaCha20Poly1305 => AEADCryptoCreate.ChaCha20Poly1305(key32),
			XChaCha20Poly1305 => AEADCryptoCreate.XChaCha20Poly1305(key32),
			_ => default
		};
	}
}
