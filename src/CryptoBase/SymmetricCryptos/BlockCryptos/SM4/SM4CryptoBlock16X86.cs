namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public class SM4CryptoBlock16X86(ReadOnlySpan<byte> key) : SM4Crypto(key)
{
	public static bool IsSupported => Aes.IsSupported && Avx2.IsSupported;

	public override int BlockSize => 256;

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));

		SM4Utils.Encrypt16(Rk, source, destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		throw new NotImplementedException();
	}
}
