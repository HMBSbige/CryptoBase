using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public abstract class DefaultAESCrypto : AESCrypto
{
	protected abstract ICryptoTransform Encryptor { get; }

	protected abstract ICryptoTransform Decryptor { get; }

	private readonly byte[] _buffer;
	private readonly byte[] _outBuffer;

	protected DefaultAESCrypto(ReadOnlySpan<byte> key) : base(key)
	{
		_buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
		_outBuffer = ArrayPool<byte>.Shared.Rent(BlockSize);
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		source.Slice(0, BlockSize).CopyTo(_buffer);
		Encryptor.TransformBlock(_buffer, 0, BlockSize, _outBuffer, 0);
		_outBuffer.CopyTo(destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		source.Slice(0, BlockSize).CopyTo(_buffer);
		Decryptor.TransformBlock(_buffer, 0, BlockSize, _outBuffer, 0);
		_outBuffer.CopyTo(destination);
	}

	public override void Dispose()
	{
		base.Dispose();

		Encryptor.Dispose();
		Decryptor.Dispose();

		ArrayPool<byte>.Shared.Return(_buffer);
		ArrayPool<byte>.Shared.Return(_outBuffer);

		GC.SuppressFinalize(this);
	}
}
