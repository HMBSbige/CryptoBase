using Aes = System.Security.Cryptography.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public sealed class DefaultAesCrypto : AesCrypto
{
	private readonly Aes _aes;

	public DefaultAesCrypto(ReadOnlySpan<byte> key) : base(key)
	{
		_aes = Aes.Create();
		_aes.Key = key.ToArray();
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);
		_aes.EncryptEcb(source.Slice(0, BlockSize), destination, PaddingMode.None);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);
		_aes.DecryptEcb(source.Slice(0, BlockSize), destination, PaddingMode.None);
	}

	public override void Encrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 2;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.EncryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Decrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 2;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.DecryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 4;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.EncryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 4;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.DecryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 8;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.EncryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 8;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.DecryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Encrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 16;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.EncryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Decrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		const int count = 16;
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, count * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, count * BlockSize, nameof(destination));

		_aes.DecryptEcb(source.Slice(0, count * BlockSize), destination, PaddingMode.None);
	}

	public override void Dispose()
	{
		_aes.Dispose();
		base.Dispose();
	}
}
