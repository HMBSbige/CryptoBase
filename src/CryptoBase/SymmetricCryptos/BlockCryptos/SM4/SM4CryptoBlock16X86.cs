namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public class SM4CryptoBlock16X86 : SM4Crypto
{
	public override int BlockSize => 256;

	public SM4CryptoBlock16X86(ReadOnlySpan<byte> key) : base(key) { }

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

		//Aes.IsSupported && Avx.IsSupported && Avx2.IsSupported
		SM4Utils.Encrypt16(Rk, source, destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		throw new NotImplementedException();
	}
}
