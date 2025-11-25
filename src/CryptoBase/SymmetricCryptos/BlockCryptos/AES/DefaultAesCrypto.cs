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

	public override VectorBuffer16 Encrypt(VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_aes.EncryptEcb(source, r, PaddingMode.None);

		return r;
	}

	public override VectorBuffer16 Decrypt(VectorBuffer16 source)
	{
		Unsafe.SkipInit(out VectorBuffer16 r);
		_aes.DecryptEcb(source, r, PaddingMode.None);

		return r;
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
