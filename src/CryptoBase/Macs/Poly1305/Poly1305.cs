namespace CryptoBase.Macs.Poly1305;

/// <summary>
/// Provides a Poly1305 implementation that zero-pads each input segment to a 16-byte boundary and selects the best available implementation.
/// </summary>
public ref struct Poly1305 : IMac
{
	/// <summary>
	/// The Poly1305 key size, in bytes.
	/// </summary>
	public const int KeySize = 32;

	/// <summary>
	/// The Poly1305 block size, in bytes.
	/// </summary>
	public const int BlockSize = 16;

	/// <summary>
	/// The Poly1305 tag size, in bytes.
	/// </summary>
	public const int TagSize = 16;

	/// <inheritdoc />
	public string Name => @"Poly1305";

	/// <inheritdoc />
	public int Length => 16;

	private Poly1305X86 _x86;
	private Poly1305SF _sf;

	/// <summary>
	/// Initializes a new instance of <see cref="Poly1305"/>.
	/// </summary>
	/// <param name="key">The <see cref="KeySize"/>-byte key.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="key"/> is not <see cref="KeySize"/> bytes long.</exception>
	public Poly1305(scoped ReadOnlySpan<byte> key)
	{
		if (Poly1305X86.IsSupported)
		{
			_x86 = new Poly1305X86(key);
		}
		else
		{
			_sf = new Poly1305SF(key);
		}
	}

	/// <inheritdoc />
	public void Update(scoped ReadOnlySpan<byte> source)
	{
		if (Poly1305X86.IsSupported)
		{
			_x86.Update(source);
		}
		else
		{
			_sf.Update(source);
		}
	}

	/// <inheritdoc />
	public void GetMac(scoped Span<byte> destination)
	{
		if (Poly1305X86.IsSupported)
		{
			_x86.GetMac(destination);
		}
		else
		{
			_sf.GetMac(destination);
		}
	}

	/// <inheritdoc />
	public void Reset()
	{
		if (Poly1305X86.IsSupported)
		{
			_x86.Reset();
		}
		else
		{
			_sf.Reset();
		}
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (Poly1305X86.IsSupported)
		{
			_x86.Dispose();
		}
		else
		{
			_sf.Dispose();
		}
	}
}
