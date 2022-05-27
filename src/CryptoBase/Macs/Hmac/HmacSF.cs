using CryptoBase.Abstractions;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CryptoBase.Macs.Hmac;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc2104
/// </summary>
internal class HmacSF : IMac
{
	public string Name => $@"HMAC-{_hasher.Name}";

	public int Length => _hasher.Length;

	private readonly IHash _hasher;
	private int KeyLength => _hasher.BlockSize;
	private readonly byte[] _oPadBuffer;
	private readonly byte[] _iPadBuffer;

	private const byte Ipad = 0x36;
	private const byte Opad = 0x5c;

	public HmacSF(ReadOnlySpan<byte> key, IHash hasher)
	{
		_hasher = hasher;

		_iPadBuffer = ArrayPool<byte>.Shared.Rent(KeyLength);
		_oPadBuffer = ArrayPool<byte>.Shared.Rent(KeyLength);
		var iSpan = _iPadBuffer.AsSpan(0, KeyLength);
		var oSpan = _oPadBuffer.AsSpan(0, KeyLength);

		if (key.Length > KeyLength)
		{
			hasher.UpdateFinal(key, iSpan);
			iSpan[hasher.Length..].Fill(0);
		}
		else
		{
			key.CopyTo(iSpan);
			iSpan[key.Length..].Fill(0);
		}

		iSpan.CopyTo(oSpan);
		XorPad(iSpan, Ipad);
		XorPad(oSpan, Opad);

		hasher.Update(iSpan);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorPad(Span<byte> pad, byte x)
	{
		for (var i = 0; i < pad.Length; ++i)
		{
			pad[i] ^= x;
		}
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		_hasher.Update(source);
	}

	public void GetMac(Span<byte> destination)
	{
		Span<byte> temp = stackalloc byte[_hasher.Length];
		_hasher.GetHash(temp);

		_hasher.Update(_oPadBuffer.AsSpan(0, KeyLength));
		_hasher.Update(temp);

		_hasher.GetHash(destination);
		_hasher.Update(_iPadBuffer.AsSpan(0, KeyLength));
	}

	public void Reset()
	{
		_hasher.Reset();
		_hasher.Update(_iPadBuffer.AsSpan(0, KeyLength));
	}

	public void Dispose()
	{
		ArrayPool<byte>.Shared.Return(_oPadBuffer);
		ArrayPool<byte>.Shared.Return(_iPadBuffer);
		_hasher.Dispose();
		GC.SuppressFinalize(this);
	}
}
