namespace CryptoBase.Macs.GHash;

/// <summary>
/// Provides a software implementation of GHASH that zero-pads each input segment to a 16-byte boundary.
/// </summary>
public sealed class GHashSF : IMac
{
	/// <inheritdoc />
	public string Name => @"GHash";

	/// <inheritdoc />
	public int Length => 16;

	/// <summary>
	/// The GHASH key size, in bytes.
	/// </summary>
	public const int KeySize = 16;

	/// <summary>
	/// The GHASH block size, in bytes.
	/// </summary>
	public const int BlockSize = 16;

	private static ReadOnlySpan<ulong> Last4 => [0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0];

	private InlineArray16<ulong> _hh;
	private InlineArray16<ulong> _hl;
	private VectorBuffer16 _buffer;

	private readonly ulong Initvh;
	private readonly ulong Initvl;

	/// <summary>
	/// Initializes a new instance of <see cref="GHashSF"/>.
	/// </summary>
	/// <param name="key">The key material. The first <see cref="KeySize"/> bytes are used.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="key"/> is shorter than <see cref="KeySize"/> bytes.</exception>
	public GHashSF(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(key.Length, KeySize, nameof(key));

		Initvh = BinaryPrimitives.ReadUInt64BigEndian(key);
		Initvl = BinaryPrimitives.ReadUInt64BigEndian(key.Slice(8));

		Reset();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void GFMul(scoped ReadOnlySpan<byte> x)
	{
		_buffer ^= x.AsVectorBuffer16();

		Span<byte> buffer = _buffer;
		Span<ulong> hh = _hh;
		Span<ulong> hl = _hl;

		byte lo = (byte)(buffer[15] & 0xF);
		ulong zh = hh[lo];
		ulong zl = hl[lo];

		for (int i = 0; i < BlockSize; ++i)
		{
			lo = (byte)(buffer[16 - 1 - i] & 0xf);
			byte hi = (byte)(buffer[16 - 1 - i] >> 4 & 0xf);

			byte rem;

			if (i != 0)
			{
				rem = (byte)(zl & 0xf);
				zl = zh << 60 | zl >> 4;
				zh >>= 4;
				zh ^= Last4[rem] << 48;
				zh ^= hh[lo];
				zl ^= hl[lo];
			}

			rem = (byte)(zl & 0xf);
			zl = zh << 60 | zl >> 4;
			zh >>= 4;

			zh ^= Last4[rem] << 48;
			zh ^= hh[hi];
			zl ^= hl[hi];
		}

		BinaryPrimitives.WriteUInt64BigEndian(buffer, zh);
		BinaryPrimitives.WriteUInt64BigEndian(buffer.Slice(8), zl);
	}

	/// <inheritdoc />
	public void Update(scoped ReadOnlySpan<byte> source)
	{
		while (source.Length >= BlockSize)
		{
			GFMul(source);
			source = source.Slice(BlockSize);
		}

		if (source.IsEmpty)
		{
			return;
		}

		Span<byte> block = stackalloc byte[BlockSize];
		source.CopyTo(block);
		GFMul(block);
	}

	/// <inheritdoc />
	public void GetMac(scoped Span<byte> destination)
	{
		Span<byte> buffer = _buffer;
		buffer.CopyTo(destination);

		Reset();
	}

	/// <inheritdoc />
	public void Reset()
	{
		_buffer = default;

		Span<ulong> hh = _hh;
		Span<ulong> hl = _hl;

		ulong vh = Initvh;
		ulong vl = Initvl;

		hl[8] = vl;
		hh[8] = vh;

		int i = 4;

		while (i > 0)
		{
			ulong t = (vl & 1) * 0xe1000000;
			vl = vh << 63 | vl >> 1;
			vh = vh >> 1 ^ t << 32;

			hl[i] = vl;
			hh[i] = vh;

			i >>= 1;
		}

		i = 2;

		while (i <= 8)
		{
			vh = hh[i];
			vl = hl[i];

			for (int j = 1; j < i; ++j)
			{
				hh[i + j] = vh ^ hh[j];
				hl[i + j] = vl ^ hl[j];
			}

			i <<= 1;
		}
	}

	/// <inheritdoc />
	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(_hl.AsSpan());
		CryptographicOperations.ZeroMemory(_hh.AsSpan());
		CryptographicOperations.ZeroMemory(_buffer);
	}
}
