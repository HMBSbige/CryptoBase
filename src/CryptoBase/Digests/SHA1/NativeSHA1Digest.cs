namespace CryptoBase.Digests.SHA1;

public class NativeSHA1Digest : IHash
{
	public string Name => @"SHA-1";
	public int Length => HashConstants.Sha1Length;
	public int BlockSize => HashConstants.Sha1BlockSize;

	private nuint _ptr;

	public NativeSHA1Digest()
	{
		_ptr = NativeMethods.sha1_new();
	}

	public unsafe void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptr = origin)
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sha1_update_final(_ptr, (nuint)ptr, (nuint)origin.Length, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public unsafe void Update(ReadOnlySpan<byte> source)
	{
		CheckIfDisposed();
		fixed (byte* ptr = source)
		{
			NativeMethods.sha1_update(_ptr, (nuint)ptr, (nuint)source.Length);
		}
	}

	public unsafe void GetHash(Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sha1_get_hash(_ptr, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public void Reset()
	{
		CheckIfDisposed();
		NativeMethods.sha1_reset(_ptr);
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
		NativeMethods.sha1_dispose(_ptr);
		_ptr = default;
		GC.SuppressFinalize(this);
	}
}
