using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc8439
/// </summary>
public class ChaCha20Cipher : SnuffleCipher
{
	/// <summary>The required key size, in bytes.</summary>
	public const int KeySize = 32;

	/// <summary>The required nonce size, in bytes.</summary>
	public const int IVSize = 12;

	/// <summary>The keystream block size, in bytes.</summary>
	public new const int BlockSize = 64;

	/// <inheritdoc />
	protected override ulong MaxCounter => uint.MaxValue;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 96-bit nonce.</param>
	public ChaCha20Cipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		InitializeKey(StateSpan, key);
		InitializeNonce(iv);
	}

	/// <summary>Initializes a new instance whose nonce must be set by <see cref="InitializeNonce" /> before use.</summary>
	internal ChaCha20Cipher(ReadOnlySpan<byte> key)
	{
		InitializeKey(StateSpan, key);
	}

	/// <summary>Initializes a new instance whose whole state must be set by the derived class before use.</summary>
	private protected ChaCha20Cipher()
	{
	}

	/// <summary>Computes the keystream block at the specified counter.</summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="nonce">The 96-bit nonce.</param>
	/// <param name="counter">The block counter.</param>
	/// <param name="destination">The buffer for the keystream block. Its length must be <see cref="BlockSize" />.</param>
	/// <remarks><paramref name="destination" /> may overlap <paramref name="key" /> or <paramref name="nonce" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <exception cref="ArgumentOutOfRangeException">A buffer has the wrong length.</exception>
	[SkipLocalsInit]
	public static void GenerateBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, IVSize, nameof(nonce));
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, BlockSize, nameof(destination));

		Unsafe.SkipInit(out InlineArray16<uint> state);
		Span<uint> stateSpan = state;
		InitializeKey(stateSpan, key);
		stateSpan[12] = counter;
		MemoryMarshal.Cast<byte, uint>(nonce.Slice(0, IVSize)).CopyTo(stateSpan.Slice(13));

		ChaCha20Utils.UpdateKeyStream(stateSpan, destination);
		state.ZeroMemory();
	}

	// Slicing the key and nonce to their validated lengths gives the copies constant sizes, which the JIT unrolls instead of calling Memmove.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InitializeKey(Span<uint> state, ReadOnlySpan<byte> key)
	{
		Debug.Assert(key.Length is KeySize);

		Sigma32.CopyTo(state);
		MemoryMarshal.Cast<byte, uint>(key.Slice(0, KeySize)).CopyTo(state.Slice(4));
	}

	/// <inheritdoc />
	protected override int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		return XorBlocks(stateSpan, source, destination);
	}

	// ChaCha20Utils.XorBlocks advances words 12-13 as one 64-bit counter; undo its carry into nonce word 13 after block 0xFFFFFFFF.
	private static int XorBlocks(Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		uint nonce0 = state[13];
		int processed = ChaCha20Utils.XorBlocks(state, source, destination);
		state[13] = nonce0;
		return processed;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.NoInlining)]
	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(StateSpan, KeyStreamSpan);
	}

	// AEAD messages stay far below 2^32 blocks, so the counter never carries into nonce word 13 here.
	internal void XorWholeBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(Index is 0 && source.Length % BlockSize is 0 && destination.Length >= source.Length);
		Debug.Assert((ulong)source.Length / BlockSize < CounterRemaining);

		ChaCha20Utils.XorBlocks(StateSpan, source, destination);
		CounterRemaining -= (uint)source.Length / BlockSize;
	}

	internal int XorChunksAndAppendPoly1305<TState>(ReadOnlySpan<byte> source, Span<byte> destination, ref TState mac, int processed, ref int hashedLength, bool decrypt) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		Debug.Assert(Index is 0 && destination.Length >= source.Length);

		int end = ChaCha20Utils.XorPoly1305(ref StateRef, ref MemoryMarshal.GetReference(source), ref MemoryMarshal.GetReference(destination), source.Length, ref mac, processed, ref hashedLength, decrypt);
		Debug.Assert((ulong)(end - processed + BlockSize - 1) / BlockSize <= CounterRemaining);
		CounterRemaining -= (uint)(end - processed + BlockSize - 1) / BlockSize;
		return end;
	}

	/// <inheritdoc />
	protected override void IncrementCounter(Span<uint> state)
	{
		++ChaCha20Utils.GetCounter(ref MemoryMarshal.GetReference(state));
	}

	/// <summary>Initializes the nonce and resets the block counter to zero.</summary>
	internal void InitializeNonce(ReadOnlySpan<byte> nonce)
	{
		Debug.Assert(nonce.Length is IVSize);

		MemoryMarshal.Cast<byte, uint>(nonce.Slice(0, IVSize)).CopyTo(StateSpan.Slice(13));
		SetCounter(0);
	}

	/// <summary>Sets the block counter and resets the byte offset within the block to zero.</summary>
	/// <param name="counter">The counter value for the next 64-byte keystream block.</param>
	public void SetCounter(uint counter)
	{
		CounterRemaining = GetBlocksRemaining(counter);
		Index = 0;
		ChaCha20Utils.GetCounter(ref StateRef) = counter;
	}
}
