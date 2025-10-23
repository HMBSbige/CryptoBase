namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public class SM4CryptoX86(ReadOnlySpan<byte> key) : SM4Crypto(key)
{
	public static bool IsSupported => Aes.IsSupported && Sse2.IsSupported && Ssse3.IsSupported;

	public override int BlockSize => 64;

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));

		SM4Utils.Encrypt4(Rk, source, destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		throw new NotImplementedException();
	}
}
