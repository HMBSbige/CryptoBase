namespace CryptoBase.Digests.MD5;

public class NativeMD5Digest : IHash
{
	public string Name => @"MD5";
	public int Length => HashConstants.Md5Length;
	public int BlockSize => HashConstants.Md5BlockSize;

	private nuint _ptr;

	public NativeMD5Digest()
	{
		_ptr = NativeMethods.md5_new();
	}

	public unsafe void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptr = origin)
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.md5_update_final(_ptr, (nuint)ptr, (nuint)origin.Length, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public unsafe void Update(ReadOnlySpan<byte> source)
	{
		CheckIfDisposed();
		fixed (byte* ptr = source)
		{
			NativeMethods.md5_update(_ptr, (nuint)ptr, (nuint)source.Length);
		}
	}

	public unsafe void GetHash(Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.md5_get_hash(_ptr, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public void Reset()
	{
		CheckIfDisposed();
		NativeMethods.md5_reset(_ptr);
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
		NativeMethods.md5_dispose(_ptr);
		_ptr = default;
		GC.SuppressFinalize(this);
	}
}
