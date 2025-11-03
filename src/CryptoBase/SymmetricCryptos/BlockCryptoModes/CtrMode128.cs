namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public class CtrMode128 : IStreamCrypto
{
	private const int BlockSize = 16;
	private const int MaxBlocks = 16;

	public string Name => _internalBlockCrypto.Name + @"-CTR";

	private readonly IBlockCrypto _internalBlockCrypto;
	private readonly bool _disposeCrypto;

	private int _index;

	private readonly CryptoArrayPool<byte> _iv = new(BlockSize);
	private readonly CryptoArrayPool<byte> _counter = new(BlockSize * MaxBlocks);
	private readonly CryptoArrayPool<byte> _keyStream = new(BlockSize * MaxBlocks);

	public CtrMode128(IBlockCrypto crypto, ReadOnlySpan<byte> iv, bool disposeCrypto = true)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(crypto.BlockSize, BlockSize);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_internalBlockCrypto = crypto;
		_disposeCrypto = disposeCrypto;

		Span<byte> ivSpan = _iv.Span;
		ivSpan.Clear();
		iv.CopyTo(_iv.Span);

		Reset();
	}

	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int i = 0;
		int left = source.Length;
		Span<byte> counter = _counter.Span;
		Span<byte> keyStream = _keyStream.Span;

		if (_index is not 0 && left > 0)
		{
			int r = BlockSize - _index;
			int n = Math.Min(r, left);

			FastUtils.XorLess16(keyStream.Slice(_index), source, destination, n);

			_index += n;
			_index &= BlockSize - 1;
			i += n;
			left -= n;
		}

		if (left >= BlockSize)
		{
			int processed = UpdateBlock(counter, keyStream, source.Slice(i), destination.Slice(i));
			i += processed;
			left -= processed;
		}

		if (left > 0)
		{
			UpdateKeyStream(counter, keyStream);

			FastUtils.XorLess16(keyStream.Slice(_index), source.Slice(i), destination.Slice(i), left);

			_index = left;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void UpdateKeyStream(in Span<byte> counter, in Span<byte> keyStream)
	{
		_internalBlockCrypto.Encrypt(counter, keyStream);

		if (Sse2.IsSupported)
		{
			ref Vector128<byte> v = ref Unsafe.As<byte, Vector128<byte>>(ref counter.GetReference());
			v = v.ReverseEndianness128().Inc128Le().ReverseEndianness128();
		}
		else
		{
			ref UInt128 c = ref Unsafe.As<byte, UInt128>(ref counter.GetReference());
			c = BinaryPrimitives.ReverseEndianness(BinaryPrimitives.ReverseEndianness(c) + 1);
		}
	}

	private int UpdateBlock(in Span<byte> counter, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int i = 0;
		int left = source.Length;
		ref byte countRef = ref counter.GetReference();

		if (left >= 16 * BlockSize
			&& _internalBlockCrypto.HardwareAcceleration.HasFlag(BlockCryptoHardwareAcceleration.Block16)
			)
		{
			if (Avx512BW.IsSupported)
			{
				ref Vector512<byte> v0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref countRef, 0 * 4 * BlockSize));
				ref Vector512<byte> v1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref countRef, 1 * 4 * BlockSize));
				ref Vector512<byte> v2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref countRef, 2 * 4 * BlockSize));
				ref Vector512<byte> v3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref countRef, 3 * 4 * BlockSize));

				Vector512<byte> t0 = FastUtils.BroadcastVector128ToVector512(ref countRef);
				t0 = t0.ReverseEndianness128().Add128Le0123();
				Vector512<byte> t1 = t0.AddFour128Le();
				Vector512<byte> t2 = t1.AddFour128Le();
				Vector512<byte> t3 = t2.AddFour128Le();

				v0 = t0.ReverseEndianness128();
				v1 = t1.ReverseEndianness128();
				v2 = t2.ReverseEndianness128();
				v3 = t3.ReverseEndianness128();

				while (left >= 16 * BlockSize)
				{
					_internalBlockCrypto.Encrypt16(counter, keyStream);

					t0 = t3.AddFour128Le();
					t1 = t0.AddFour128Le();
					t2 = t1.AddFour128Le();
					t3 = t2.AddFour128Le();

					v0 = t0.ReverseEndianness128();
					v1 = t1.ReverseEndianness128();
					v2 = t2.ReverseEndianness128();
					v3 = t3.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 16 * BlockSize);

					i += 16 * BlockSize;
					left -= 16 * BlockSize;
				}
			}
			else if (Avx2.IsSupported)
			{
				ref Vector256<byte> v0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 0 * 2 * BlockSize));
				ref Vector256<byte> v1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 1 * 2 * BlockSize));
				ref Vector256<byte> v2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 2 * 2 * BlockSize));
				ref Vector256<byte> v3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 3 * 2 * BlockSize));
				ref Vector256<byte> v4 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 4 * 2 * BlockSize));
				ref Vector256<byte> v5 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 5 * 2 * BlockSize));
				ref Vector256<byte> v6 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 6 * 2 * BlockSize));
				ref Vector256<byte> v7 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 7 * 2 * BlockSize));

				Vector256<byte> t0 = FastUtils.BroadcastVector128ToVector256(ref countRef);
				t0 = t0.ReverseEndianness128().IncUpper128Le();
				Vector256<byte> t1 = t0.AddTwo128Le();
				Vector256<byte> t2 = t1.AddTwo128Le();
				Vector256<byte> t3 = t2.AddTwo128Le();
				Vector256<byte> t4 = t3.AddTwo128Le();
				Vector256<byte> t5 = t4.AddTwo128Le();
				Vector256<byte> t6 = t5.AddTwo128Le();
				Vector256<byte> t7 = t6.AddTwo128Le();

				v0 = t0.ReverseEndianness128();
				v1 = t1.ReverseEndianness128();
				v2 = t2.ReverseEndianness128();
				v3 = t3.ReverseEndianness128();
				v4 = t4.ReverseEndianness128();
				v5 = t5.ReverseEndianness128();
				v6 = t6.ReverseEndianness128();
				v7 = t7.ReverseEndianness128();

				while (left >= 16 * BlockSize)
				{
					_internalBlockCrypto.Encrypt16(counter, keyStream);

					t0 = t7.AddTwo128Le();
					t1 = t0.AddTwo128Le();
					t2 = t1.AddTwo128Le();
					t3 = t2.AddTwo128Le();
					t4 = t3.AddTwo128Le();
					t5 = t4.AddTwo128Le();
					t6 = t5.AddTwo128Le();
					t7 = t6.AddTwo128Le();

					v0 = t0.ReverseEndianness128();
					v1 = t1.ReverseEndianness128();
					v2 = t2.ReverseEndianness128();
					v3 = t3.ReverseEndianness128();
					v4 = t4.ReverseEndianness128();
					v5 = t5.ReverseEndianness128();
					v6 = t6.ReverseEndianness128();
					v7 = t7.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 16 * BlockSize);

					i += 16 * BlockSize;
					left -= 16 * BlockSize;
				}
			}
		}

		if (left >= 8 * BlockSize)
		{
			if (Avx2.IsSupported)
			{
				ref Vector256<byte> v0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 0 * 2 * BlockSize));
				ref Vector256<byte> v1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 1 * 2 * BlockSize));
				ref Vector256<byte> v2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 2 * 2 * BlockSize));
				ref Vector256<byte> v3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref countRef, 3 * 2 * BlockSize));

				Vector256<byte> t0 = FastUtils.BroadcastVector128ToVector256(ref countRef);
				t0 = t0.ReverseEndianness128().IncUpper128Le();
				Vector256<byte> t1 = t0.AddTwo128Le();
				Vector256<byte> t2 = t1.AddTwo128Le();
				Vector256<byte> t3 = t2.AddTwo128Le();

				v0 = t0.ReverseEndianness128();
				v1 = t1.ReverseEndianness128();
				v2 = t2.ReverseEndianness128();
				v3 = t3.ReverseEndianness128();

				while (left >= 8 * BlockSize)
				{
					_internalBlockCrypto.Encrypt8(counter, keyStream);

					t0 = t3.AddTwo128Le();
					t1 = t0.AddTwo128Le();
					t2 = t1.AddTwo128Le();
					t3 = t2.AddTwo128Le();

					v0 = t0.ReverseEndianness128();
					v1 = t1.ReverseEndianness128();
					v2 = t2.ReverseEndianness128();
					v3 = t3.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 8 * BlockSize);

					i += 8 * BlockSize;
					left -= 8 * BlockSize;
				}

				if (left >= 4 * BlockSize)
				{
					_internalBlockCrypto.Encrypt4(counter, keyStream);

					t0 = t1.AddTwo128Le();
					v0 = t0.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 4 * BlockSize);

					i += 4 * BlockSize;
					left -= 4 * BlockSize;
				}

				if (left >= 2 * BlockSize)
				{
					t0 = t0.AddTwo128Le();

					_internalBlockCrypto.Encrypt2(counter, keyStream);

					v0 = t0.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 2 * BlockSize);

					i += 2 * BlockSize;
					left -= 2 * BlockSize;
				}
			}
			else if (Sse2.IsSupported)
			{
				ref Vector128<byte> v0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 0 * BlockSize));
				ref Vector128<byte> v1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 1 * BlockSize));
				ref Vector128<byte> v2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 2 * BlockSize));
				ref Vector128<byte> v3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 3 * BlockSize));
				ref Vector128<byte> v4 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 4 * BlockSize));
				ref Vector128<byte> v5 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 5 * BlockSize));
				ref Vector128<byte> v6 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 6 * BlockSize));
				ref Vector128<byte> v7 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref countRef, 7 * BlockSize));

				Vector128<byte> t1 = v0.ReverseEndianness128().Inc128Le();
				Vector128<byte> t2 = t1.Inc128Le();
				Vector128<byte> t3 = t2.Inc128Le();
				Vector128<byte> t4 = t3.Inc128Le();
				Vector128<byte> t5 = t4.Inc128Le();
				Vector128<byte> t6 = t5.Inc128Le();
				Vector128<byte> t7 = t6.Inc128Le();

				v1 = t1.ReverseEndianness128();
				v2 = t2.ReverseEndianness128();
				v3 = t3.ReverseEndianness128();
				v4 = t4.ReverseEndianness128();
				v5 = t5.ReverseEndianness128();
				v6 = t6.ReverseEndianness128();
				v7 = t7.ReverseEndianness128();

				while (left >= 8 * BlockSize)
				{
					_internalBlockCrypto.Encrypt8(counter, keyStream);

					Vector128<byte> t0 = t7.Inc128Le();
					t1 = t0.Inc128Le();
					t2 = t1.Inc128Le();
					t3 = t2.Inc128Le();
					t4 = t3.Inc128Le();
					t5 = t4.Inc128Le();
					t6 = t5.Inc128Le();
					t7 = t6.Inc128Le();

					v0 = t0.ReverseEndianness128();
					v1 = t1.ReverseEndianness128();
					v2 = t2.ReverseEndianness128();
					v3 = t3.ReverseEndianness128();
					v4 = t4.ReverseEndianness128();
					v5 = t5.ReverseEndianness128();
					v6 = t6.ReverseEndianness128();
					v7 = t7.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 8 * BlockSize);
					i += 8 * BlockSize;
					left -= 8 * BlockSize;
				}

				if (left >= 4 * BlockSize)
				{
					_internalBlockCrypto.Encrypt4(counter, keyStream);

					Vector128<byte> t0 = t3.Inc128Le();
					t1 = t0.Inc128Le();

					v0 = t0.ReverseEndianness128();
					v1 = t1.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 4 * BlockSize);

					i += 4 * BlockSize;
					left -= 4 * BlockSize;
				}

				if (left >= 2 * BlockSize)
				{
					Vector128<byte> t0 = t1.Inc128Le();

					_internalBlockCrypto.Encrypt2(counter, keyStream);

					v0 = t0.ReverseEndianness128();

					FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), 2 * BlockSize);

					i += 2 * BlockSize;
					left -= 2 * BlockSize;
				}
			}
		}

		while (left >= BlockSize)
		{
			UpdateKeyStream(counter, keyStream);

			FastUtils.Xor16(keyStream, source.Slice(i), destination.Slice(i));

			i += BlockSize;
			left -= BlockSize;
		}

		return source.Length - left;
	}

	public void Reset()
	{
		_index = 0;
		_iv.Span.CopyTo(_counter.Span);
	}

	public void Dispose()
	{
		_iv.Dispose();
		_counter.Dispose();
		_keyStream.Dispose();

		if (_disposeCrypto)
		{
			_internalBlockCrypto.Dispose();
		}

		GC.SuppressFinalize(this);
	}
}
