namespace CryptoBase.Macs.Poly1305;

public ref struct Poly1305 : IMac
{
	public const int KeySize = 32;
	public const int BlockSize = 16;
	public const int TagSize = 16;

	public string Name => @"Poly1305";

	public int Length => 16;

	private Poly1305X86 _x86;
	private Poly1305SF _sf;

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
