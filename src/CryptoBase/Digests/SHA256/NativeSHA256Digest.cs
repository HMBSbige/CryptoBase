namespace CryptoBase.Digests.SHA256;

public class NativeSHA256Digest : IHash
{
	public string Name => @"SHA-256";
	public int Length => HashConstants.Sha256Length;
	public int BlockSize => HashConstants.Sha256BlockSize;

	private nuint _ptr;

	public NativeSHA256Digest()
	{
		_ptr = NativeMethods.sha256_new();
	}

	public unsafe void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptr = origin)
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sha256_update_final(_ptr, (nuint)ptr, (nuint)origin.Length, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public unsafe void Update(ReadOnlySpan<byte> source)
	{
		CheckIfDisposed();
		fixed (byte* ptr = source)
		{
			NativeMethods.sha256_update(_ptr, (nuint)ptr, (nuint)source.Length);
		}
	}

	public unsafe void GetHash(Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sha256_get_hash(_ptr, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public void Reset()
	{
		CheckIfDisposed();
		NativeMethods.sha256_reset(_ptr);
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
		NativeMethods.sha256_dispose(_ptr);
		_ptr = default;
		GC.SuppressFinalize(this);
	}
}
