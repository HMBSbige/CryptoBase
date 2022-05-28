namespace CryptoBase.Digests.SM3;

public class NativeSM3Digest : IHash
{
	public string Name => @"SM3";
	public int Length => HashConstants.SM3Length;
	public int BlockSize => HashConstants.SM3BlockSize;

	private nuint _ptr;

	public NativeSM3Digest()
	{
		_ptr = NativeMethods.sm3_new();
	}

	public unsafe void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptr = origin)
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sm3_update_final(_ptr, (nuint)ptr, (nuint)origin.Length, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public unsafe void Update(ReadOnlySpan<byte> source)
	{
		CheckIfDisposed();
		fixed (byte* ptr = source)
		{
			NativeMethods.sm3_update(_ptr, (nuint)ptr, (nuint)source.Length);
		}
	}

	public unsafe void GetHash(Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sm3_get_hash(_ptr, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public void Reset()
	{
		CheckIfDisposed();
		NativeMethods.sm3_reset(_ptr);
	}

	private void CheckIfDisposed()
	{
		if (_ptr == default)
		{
			throw new ObjectDisposedException(GetType().FullName);
		}
	}

	public void Dispose()
	{
		CheckIfDisposed();
		NativeMethods.sm3_dispose(_ptr);
		_ptr = default;
		GC.SuppressFinalize(this);
	}
}
