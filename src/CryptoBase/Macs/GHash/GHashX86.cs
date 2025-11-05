using CryptoBase.Abstractions;

namespace CryptoBase.Macs.GHash;

public sealed class GHashX86 : IMac
{
	public string Name => @"GHash";

	public int Length => 16;

	public static bool IsSupported => Sse2.IsSupported && Pclmulqdq.IsSupported;

	public static bool IsSupported256 => Avx2.IsSupported && Pclmulqdq.V256.IsSupported;

	public static bool IsSupported512 => Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported;

	public const int KeySize = 16;
	public const int BlockSize = 16;

	private readonly Vector128<byte> _key1;
	private readonly Vector128<byte> _key2;
	private readonly Vector128<byte> _key3;
	private readonly Vector128<byte> _key4;
	private readonly Vector128<byte> _key5;
	private readonly Vector128<byte> _key6;
	private readonly Vector128<byte> _key7;
	private readonly Vector128<byte> _key8;

	private readonly Vector256<byte> _key21;
	private readonly Vector256<byte> _key43;
	private readonly Vector256<byte> _key65;
	private readonly Vector256<byte> _key87;
	private readonly Vector256<byte> _key109;
	private readonly Vector256<byte> _key1211;
	private readonly Vector256<byte> _key1413;
	private readonly Vector256<byte> _key1615;

	private readonly Vector512<byte> _key4321;
	private readonly Vector512<byte> _key8765;
	private readonly Vector512<byte> _key1211109;
	private readonly Vector512<byte> _key16151413;
	private readonly Vector512<byte> _key20191817;
	private readonly Vector512<byte> _key24132221;
	private readonly Vector512<byte> _key28272625;
	private readonly Vector512<byte> _key32313029;
	private readonly Vector512<byte> _key36353433;
	private readonly Vector512<byte> _key40393837;
	private readonly Vector512<byte> _key44434241;
	private readonly Vector512<byte> _key48474645;
	private readonly Vector512<byte> _key52415049;
	private readonly Vector512<byte> _key56555453;
	private readonly Vector512<byte> _key60595857;
	private readonly Vector512<byte> _key64636261;

	private Vector128<byte> _buffer;

	public GHashX86(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(key.Length, KeySize, nameof(key));

		ref readonly Vector128<byte> v = ref Unsafe.As<byte, Vector128<byte>>(ref key.GetReference());
		_key1 = v.ReverseEndianness128();

		_key2 = GHashUtils.GfMultiply(_key1, _key1);
		_key3 = GHashUtils.GfMultiply(_key2, _key1);
		_key4 = GHashUtils.GfMultiply(_key3, _key1);
		_key5 = GHashUtils.GfMultiply(_key4, _key1);
		_key6 = GHashUtils.GfMultiply(_key5, _key1);
		_key7 = GHashUtils.GfMultiply(_key6, _key1);
		_key8 = GHashUtils.GfMultiply(_key7, _key1);

		if (IsSupported256)
		{
			_key21 = Vector256.Create(_key2, _key1);
			_key43 = Vector256.Create(_key4, _key3);
			_key65 = Vector256.Create(_key6, _key5);
			_key87 = Vector256.Create(_key8, _key7);

			Vector256<byte> key22 = Vector256.Create(_key2, _key2);

			_key109 = GHashUtils.GfMultiply(_key87, key22);
			_key1211 = GHashUtils.GfMultiply(_key109, key22);
			_key1413 = GHashUtils.GfMultiply(_key1211, key22);
			_key1615 = GHashUtils.GfMultiply(_key1413, key22);

			if (IsSupported512)
			{
				_key4321 = Vector512.Create(_key43, _key21);
				_key8765 = Vector512.Create(_key87, _key65);
				_key1211109 = Vector512.Create(_key1211, _key109);
				_key16151413 = Vector512.Create(_key1615, _key1413);

				Vector256<byte> key44 = Vector256.Create(_key4, _key4);
				Vector512<byte> key4444 = Vector512.Create(key44, key44);

				_key20191817 = GHashUtils.GfMultiply(_key16151413, key4444);
				_key24132221 = GHashUtils.GfMultiply(_key20191817, key4444);
				_key28272625 = GHashUtils.GfMultiply(_key24132221, key4444);
				_key32313029 = GHashUtils.GfMultiply(_key28272625, key4444);
				_key36353433 = GHashUtils.GfMultiply(_key32313029, key4444);
				_key40393837 = GHashUtils.GfMultiply(_key36353433, key4444);
				_key44434241 = GHashUtils.GfMultiply(_key40393837, key4444);
				_key48474645 = GHashUtils.GfMultiply(_key44434241, key4444);
				_key52415049 = GHashUtils.GfMultiply(_key48474645, key4444);
				_key56555453 = GHashUtils.GfMultiply(_key52415049, key4444);
				_key60595857 = GHashUtils.GfMultiply(_key56555453, key4444);
				_key64636261 = GHashUtils.GfMultiply(_key60595857, key4444);
			}
		}

		Reset();
	}

	public void Update(scoped ReadOnlySpan<byte> source)
	{
		int offset = 0;
		int length = source.Length;
		ref byte ptr = ref source.GetReference();

		if (IsSupported512)
		{
			while (length >= 64 * BlockSize)
			{
				Vector512<byte> x0 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x1 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x2 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x3 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x4 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 4 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x5 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 5 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x6 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 6 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x7 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 7 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x8 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 8 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x9 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 9 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x10 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 10 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x11 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 11 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x12 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 12 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x13 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 13 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x14 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 14 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x15 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 15 * 4 * BlockSize)).ReverseEndianness128();

				ref Vector128<byte> x0Lower = ref Unsafe.As<Vector512<byte>, Vector128<byte>>(ref x0);
				x0Lower ^= _buffer;

				GHashUtils.GfMultiply(_key64636261, x0, out Vector512<uint> lo0, out Vector512<uint> hi0);
				GHashUtils.GfMultiply(_key60595857, x1, out Vector512<uint> lo1, out Vector512<uint> hi1);
				GHashUtils.GfMultiply(_key56555453, x2, out Vector512<uint> lo2, out Vector512<uint> hi2);
				GHashUtils.GfMultiply(_key52415049, x3, out Vector512<uint> lo3, out Vector512<uint> hi3);
				GHashUtils.GfMultiply(_key48474645, x4, out Vector512<uint> lo4, out Vector512<uint> hi4);
				GHashUtils.GfMultiply(_key44434241, x5, out Vector512<uint> lo5, out Vector512<uint> hi5);
				GHashUtils.GfMultiply(_key40393837, x6, out Vector512<uint> lo6, out Vector512<uint> hi6);
				GHashUtils.GfMultiply(_key36353433, x7, out Vector512<uint> lo7, out Vector512<uint> hi7);
				GHashUtils.GfMultiply(_key32313029, x8, out Vector512<uint> lo8, out Vector512<uint> hi8);
				GHashUtils.GfMultiply(_key28272625, x9, out Vector512<uint> lo9, out Vector512<uint> hi9);
				GHashUtils.GfMultiply(_key24132221, x10, out Vector512<uint> lo10, out Vector512<uint> hi10);
				GHashUtils.GfMultiply(_key20191817, x11, out Vector512<uint> lo11, out Vector512<uint> hi11);
				GHashUtils.GfMultiply(_key16151413, x12, out Vector512<uint> lo12, out Vector512<uint> hi12);
				GHashUtils.GfMultiply(_key1211109, x13, out Vector512<uint> lo13, out Vector512<uint> hi13);
				GHashUtils.GfMultiply(_key8765, x14, out Vector512<uint> lo14, out Vector512<uint> hi14);
				GHashUtils.GfMultiply(_key4321, x15, out Vector512<uint> lo15, out Vector512<uint> hi15);

				Vector512<uint> lo = lo0 ^ lo1 ^ lo2 ^ lo3 ^ lo4 ^ lo5 ^ lo6 ^ lo7 ^ lo8 ^ lo9 ^ lo10 ^ lo11 ^ lo12 ^ lo13 ^ lo14 ^ lo15;
				Vector512<uint> hi = hi0 ^ hi1 ^ hi2 ^ hi3 ^ hi4 ^ hi5 ^ hi6 ^ hi7 ^ hi8 ^ hi9 ^ hi10 ^ hi11 ^ hi12 ^ hi13 ^ hi14 ^ hi15;

				_buffer = GHashUtils.ReduceTo128(lo, hi);

				offset += 64 * BlockSize;
				length -= 64 * BlockSize;
			}

			if (length >= 32 * BlockSize)
			{
				Vector512<byte> x0 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x1 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x2 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x3 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x4 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 4 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x5 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 5 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x6 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 6 * 4 * BlockSize)).ReverseEndianness128();
				Vector512<byte> x7 = Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, offset + 7 * 4 * BlockSize)).ReverseEndianness128();

				ref Vector128<byte> x0Lower = ref Unsafe.As<Vector512<byte>, Vector128<byte>>(ref x0);
				x0Lower ^= _buffer;

				GHashUtils.GfMultiply(_key32313029, x0, out Vector512<uint> lo0, out Vector512<uint> hi0);
				GHashUtils.GfMultiply(_key28272625, x1, out Vector512<uint> lo1, out Vector512<uint> hi1);
				GHashUtils.GfMultiply(_key24132221, x2, out Vector512<uint> lo2, out Vector512<uint> hi2);
				GHashUtils.GfMultiply(_key20191817, x3, out Vector512<uint> lo3, out Vector512<uint> hi3);
				GHashUtils.GfMultiply(_key16151413, x4, out Vector512<uint> lo4, out Vector512<uint> hi4);
				GHashUtils.GfMultiply(_key1211109, x5, out Vector512<uint> lo5, out Vector512<uint> hi5);
				GHashUtils.GfMultiply(_key8765, x6, out Vector512<uint> lo6, out Vector512<uint> hi6);
				GHashUtils.GfMultiply(_key4321, x7, out Vector512<uint> lo7, out Vector512<uint> hi7);

				Vector512<uint> lo = lo0 ^ lo1 ^ lo2 ^ lo3 ^ lo4 ^ lo5 ^ lo6 ^ lo7;
				Vector512<uint> hi = hi0 ^ hi1 ^ hi2 ^ hi3 ^ hi4 ^ hi5 ^ hi6 ^ hi7;

				_buffer = GHashUtils.ReduceTo128(lo, hi);

				offset += 32 * BlockSize;
				length -= 32 * BlockSize;
			}
		}

		if (IsSupported256)
		{
			while (length >= 16 * BlockSize)
			{
				Vector256<byte> x0 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x1 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x2 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x3 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x4 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 4 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x5 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 5 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x6 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 6 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x7 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 7 * 2 * BlockSize)).ReverseEndianness128();

				ref Vector128<byte> x0Lower = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref x0);
				x0Lower ^= _buffer;

				GHashUtils.GfMultiply(_key1615, x0, out Vector256<uint> lo0, out Vector256<uint> hi0);
				GHashUtils.GfMultiply(_key1413, x1, out Vector256<uint> lo1, out Vector256<uint> hi1);
				GHashUtils.GfMultiply(_key1211, x2, out Vector256<uint> lo2, out Vector256<uint> hi2);
				GHashUtils.GfMultiply(_key109, x3, out Vector256<uint> lo3, out Vector256<uint> hi3);
				GHashUtils.GfMultiply(_key87, x4, out Vector256<uint> lo4, out Vector256<uint> hi4);
				GHashUtils.GfMultiply(_key65, x5, out Vector256<uint> lo5, out Vector256<uint> hi5);
				GHashUtils.GfMultiply(_key43, x6, out Vector256<uint> lo6, out Vector256<uint> hi6);
				GHashUtils.GfMultiply(_key21, x7, out Vector256<uint> lo7, out Vector256<uint> hi7);
				Vector256<uint> lo = lo0 ^ lo1 ^ lo2 ^ lo3 ^ lo4 ^ lo5 ^ lo6 ^ lo7;
				Vector256<uint> hi = hi0 ^ hi1 ^ hi2 ^ hi3 ^ hi4 ^ hi5 ^ hi6 ^ hi7;

				_buffer = GHashUtils.ReduceTo128(lo, hi);

				offset += 16 * BlockSize;
				length -= 16 * BlockSize;
			}

			if (length >= 8 * BlockSize)
			{
				Vector256<byte> x0 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x1 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x2 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * 2 * BlockSize)).ReverseEndianness128();
				Vector256<byte> x3 = Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * 2 * BlockSize)).ReverseEndianness128();

				ref Vector128<byte> x0Lower = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref x0);
				x0Lower ^= _buffer;

				GHashUtils.GfMultiply(_key87, x0, out Vector256<uint> lo0, out Vector256<uint> hi0);
				GHashUtils.GfMultiply(_key65, x1, out Vector256<uint> lo1, out Vector256<uint> hi1);
				GHashUtils.GfMultiply(_key43, x2, out Vector256<uint> lo2, out Vector256<uint> hi2);
				GHashUtils.GfMultiply(_key21, x3, out Vector256<uint> lo3, out Vector256<uint> hi3);
				Vector256<uint> lo = lo0 ^ lo1 ^ lo2 ^ lo3;
				Vector256<uint> hi = hi0 ^ hi1 ^ hi2 ^ hi3;

				_buffer = GHashUtils.ReduceTo128(lo, hi);

				offset += 8 * BlockSize;
				length -= 8 * BlockSize;
			}
		}

		while (length >= 8 * BlockSize)
		{
			Vector128<byte> x0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x4 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 4 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x5 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 5 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x6 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 6 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x7 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 7 * BlockSize)).ReverseEndianness128();
			x0 ^= _buffer;

			GHashUtils.GfMultiply(_key8, x0, out Vector128<uint> lo0, out Vector128<uint> hi0);
			GHashUtils.GfMultiply(_key7, x1, out Vector128<uint> lo1, out Vector128<uint> hi1);
			GHashUtils.GfMultiply(_key6, x2, out Vector128<uint> lo2, out Vector128<uint> hi2);
			GHashUtils.GfMultiply(_key5, x3, out Vector128<uint> lo3, out Vector128<uint> hi3);
			Vector128<uint> lo = lo0 ^ lo1 ^ lo2 ^ lo3;
			Vector128<uint> hi = hi0 ^ hi1 ^ hi2 ^ hi3;

			GHashUtils.GfMultiply(_key4, x4, out Vector128<uint> lo4, out Vector128<uint> hi4);
			GHashUtils.GfMultiply(_key3, x5, out Vector128<uint> lo5, out Vector128<uint> hi5);
			GHashUtils.GfMultiply(_key2, x6, out Vector128<uint> lo6, out Vector128<uint> hi6);
			GHashUtils.GfMultiply(_key1, x7, out Vector128<uint> lo7, out Vector128<uint> hi7);
			lo ^= lo4 ^ lo5 ^ lo6 ^ lo7;
			hi ^= hi4 ^ hi5 ^ hi6 ^ hi7;

			_buffer = GHashUtils.Reduce(lo, hi);

			offset += 8 * BlockSize;
			length -= 8 * BlockSize;
		}

		if (length >= 4 * BlockSize)
		{
			Vector128<byte> x0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * BlockSize)).ReverseEndianness128();
			x0 ^= _buffer;

			GHashUtils.GfMultiply(_key4, x0, out Vector128<uint> lo0, out Vector128<uint> hi0);
			GHashUtils.GfMultiply(_key3, x1, out Vector128<uint> lo1, out Vector128<uint> hi1);
			GHashUtils.GfMultiply(_key2, x2, out Vector128<uint> lo2, out Vector128<uint> hi2);
			GHashUtils.GfMultiply(_key1, x3, out Vector128<uint> lo3, out Vector128<uint> hi3);
			Vector128<uint> lo = lo0 ^ lo1 ^ lo2 ^ lo3;
			Vector128<uint> hi = hi0 ^ hi1 ^ hi2 ^ hi3;

			_buffer = GHashUtils.Reduce(lo, hi);

			offset += 4 * BlockSize;
			length -= 4 * BlockSize;
		}

		if (length >= 2 * BlockSize)
		{
			Vector128<byte> x0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();
			x0 ^= _buffer;

			GHashUtils.GfMultiply(_key2, x0, out Vector128<uint> lo0, out Vector128<uint> hi0);
			GHashUtils.GfMultiply(_key1, x1, out Vector128<uint> lo1, out Vector128<uint> hi1);
			Vector128<uint> lo = lo0 ^ lo1;
			Vector128<uint> hi = hi0 ^ hi1;

			_buffer = GHashUtils.Reduce(lo, hi);

			offset += 2 * BlockSize;
			length -= 2 * BlockSize;
		}

		if (length >= BlockSize)
		{
			Vector128<byte> v = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset)).ReverseEndianness128();
			_buffer = GHashUtils.GfMultiply(_key1, v ^ _buffer);

			offset += BlockSize;
			length -= BlockSize;
		}

		if (length is not 0)
		{
			Span<byte> block = stackalloc byte[BlockSize];
			source.Slice(offset).CopyTo(block);

			Vector128<byte> v = Unsafe.As<byte, Vector128<byte>>(ref block.GetReference()).ReverseEndianness128();
			_buffer = GHashUtils.GfMultiply(_key1, v ^ _buffer);
		}
	}

	public void GetMac(scoped Span<byte> destination)
	{
		_buffer.ReverseEndianness128().CopyTo(destination);
		Reset();
	}

	public void Reset()
	{
		_buffer = default;
	}

	public void Dispose()
	{
	}
}
