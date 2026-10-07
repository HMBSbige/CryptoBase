namespace CryptoBase.Ciphers.Modes.Ccm;

internal readonly ref struct BufferedCcmBlockEncryptor<TBlockCipher> : ICcmBlockEncryptor where TBlockCipher : IBlockEncryptor<TBlockCipher>
{
	internal const int BufferSize = 32;

	private readonly TBlockCipher _cipher;
	private readonly Span<byte> _buffer;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal BufferedCcmBlockEncryptor(TBlockCipher cipher, Span<byte> buffer)
	{
		Debug.Assert(buffer.Length is BufferSize);
		_cipher = cipher;
		_buffer = buffer;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Begin(ref Vector128<byte> state, ref Vector128<byte> counterBlock)
	{
		Encrypt2(ref state, ref counterBlock);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Absorb(ref Vector128<byte> state, Vector128<byte> block)
	{
		Span<byte> buffer = _buffer.Slice(0, 16);
		(state ^ block).StoreUnsafe(ref buffer.GetReference());
		_cipher.EncryptBlock(buffer, buffer);
		state = Vector128.LoadUnsafe(ref buffer.GetReference());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Absorb(ref Vector128<byte> state, Vector128<byte> block, ref Vector128<byte> counterBlock)
	{
		state ^= block;
		Encrypt2(ref state, ref counterBlock);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Finish(Vector128<byte> state)
	{
		return state;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Encrypt2(ref Vector128<byte> v0, ref Vector128<byte> v1)
	{
		ref byte buffer = ref _buffer.GetReference();
		v0.StoreUnsafe(ref buffer);
		v1.StoreUnsafe(ref buffer, 16);
		_cipher.EncryptBlocks(_buffer, _buffer);
		v0 = Vector128.LoadUnsafe(ref buffer);
		v1 = Vector128.LoadUnsafe(ref buffer, 16);
	}
}
