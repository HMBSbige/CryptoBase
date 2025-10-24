using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Xts;

public sealed class XtsMode : BlockCryptoBase
{
	private readonly Vector128<byte> _iv;

	public override string Name => _dataCrypto.Name + @"-XTS";

	public override int BlockSize => 16;

	private readonly IBlockCrypto _dataCrypto;
	private readonly IBlockCrypto _tweakCrypto;

	public XtsMode(IBlockCrypto dataCrypto, IBlockCrypto tweakCrypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(dataCrypto.BlockSize, BlockSize, nameof(dataCrypto));
		ArgumentOutOfRangeException.ThrowIfNotEqual(tweakCrypto.BlockSize, BlockSize, nameof(tweakCrypto));
		ArgumentOutOfRangeException.ThrowIfLessThan(iv.Length, BlockSize, nameof(iv));

		_dataCrypto = dataCrypto;
		_tweakCrypto = tweakCrypto;
		_iv = Unsafe.ReadUnaligned<Vector128<byte>>(ref MemoryMarshal.GetReference(iv));
	}

	[SkipLocalsInit]
	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		ReadOnlySpan<byte> iv = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<Vector128<byte>, byte>(ref Unsafe.AsRef(in _iv)), BlockSize);

		using CryptoBuffer cryptoBuffer = new(stackalloc byte[BlockSize]);
		Span<byte> tweak = cryptoBuffer.Span;
		_tweakCrypto.Encrypt(iv, tweak);
		IBlockCrypto crypto = _dataCrypto;

		int left = source.Length % BlockSize;
		int size = source.Length - left;

		using (CryptoBuffer buffer = new(size))
		{
			Span<byte> tweakBuffer = buffer.Span;

			for (int i = 0; i < size; i += BlockSize)
			{
				tweak.CopyTo(tweakBuffer.Slice(i));
				Gf128Mul(ref tweak);
			}

			FastUtils.Xor(source, tweakBuffer, destination, size);

			for (int i = 0; i < size; i += BlockSize)
			{
				Span<byte> block = destination.Slice(i, BlockSize);
				crypto.Encrypt(block, block);
			}

			FastUtils.Xor(destination, tweakBuffer, size);
		}

		if (left is not 0)
		{
			Span<byte> lastDSt = destination.Slice(size - BlockSize, BlockSize);

			lastDSt.Slice(0, left).CopyTo(destination.Slice(size));
			source.Slice(size).CopyTo(lastDSt);

			FastUtils.Xor16(lastDSt, tweak);
			crypto.Encrypt(lastDSt, lastDSt);
			FastUtils.Xor16(lastDSt, tweak);
		}
	}

	[SkipLocalsInit]
	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		ReadOnlySpan<byte> iv = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<Vector128<byte>, byte>(ref Unsafe.AsRef(in _iv)), BlockSize);
		using CryptoBuffer cryptoBuffer = new(stackalloc byte[BlockSize]);
		Span<byte> tweak = cryptoBuffer.Span;
		_tweakCrypto.Encrypt(iv, tweak);
		IBlockCrypto crypto = _dataCrypto;

		int left = source.Length % BlockSize;
		int size = source.Length - left - (BlockSize & (left | -left) >> 31);

		using (CryptoBuffer buffer = new(size))
		{
			Span<byte> tweakBuffer = buffer.Span;

			for (int i = 0; i < size; i += BlockSize)
			{
				tweak.CopyTo(tweakBuffer.Slice(i));
				Gf128Mul(ref tweak);
			}

			FastUtils.Xor(source, tweakBuffer, destination, size);

			for (int i = 0; i < size; i += BlockSize)
			{
				Span<byte> block = destination.Slice(i, BlockSize);
				crypto.Decrypt(block, block);
			}

			FastUtils.Xor(destination, tweakBuffer, size);
		}

		if (left is not 0)
		{
			using CryptoBuffer buffer = new(stackalloc byte[BlockSize]);
			Span<byte> finalTweak = buffer.Span;
			tweak.CopyTo(finalTweak);
			Gf128Mul(ref finalTweak);

			ReadOnlySpan<byte> lastSrc = source.Slice(size);
			Span<byte> lastDst = destination.Slice(size);

			FastUtils.Xor16(lastSrc, finalTweak, lastDst);
			_dataCrypto.Decrypt(lastDst, lastDst);
			FastUtils.Xor16(lastDst, finalTweak);

			lastDst.Slice(0, left).CopyTo(lastDst.Slice(BlockSize));
			lastSrc.Slice(BlockSize, left).CopyTo(lastDst);

			FastUtils.Xor16(lastDst, tweak);
			_dataCrypto.Decrypt(lastDst, lastDst);
			FastUtils.Xor16(lastDst, tweak);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul(ref Span<byte> buffer)
	{
		ref ulong v0 = ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(buffer));
		ref ulong v1 = ref Unsafe.As<byte, ulong>(ref buffer.GetRef(8));

		ulong t = (ulong)((long)v1 >> 63 & 0x87);

		v1 = v1 << 1 | v0 >> 63;
		v0 = v0 << 1 ^ t;
	}

	public override void Reset()
	{
		_dataCrypto.Reset();
		_tweakCrypto.Reset();
	}

	public override void Dispose()
	{
		_dataCrypto.Dispose();
		_tweakCrypto.Dispose();
	}
}
