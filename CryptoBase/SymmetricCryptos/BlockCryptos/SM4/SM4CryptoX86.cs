namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public class SM4CryptoX86 : SM4Crypto
{
	public override int BlockSize => 64;

	public SM4CryptoX86(ReadOnlySpan<byte> key) : base(key) { }

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

		//Aes.IsSupported && Sse2.IsSupported && Ssse3.IsSupported
		SM4Utils.Encrypt4(Rk, source, destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		throw new NotImplementedException();
	}
}
