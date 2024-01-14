namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public class SM4CryptoBlock8X86(ReadOnlySpan<byte> key) : SM4Crypto(key)
{
	public static bool IsSupported => Aes.IsSupported && Sse2.IsSupported && Ssse3.IsSupported;

	public override int BlockSize => 128;

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (source.Length < BlockSize)
		{
			throw new ArgumentException(string.Empty, nameof(source));
		}

		if (destination.Length < BlockSize)
		{
			throw new ArgumentException(string.Empty, nameof(destination));
		}

		SM4Utils.Encrypt8(Rk, source, destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		throw new NotImplementedException();
	}
}
