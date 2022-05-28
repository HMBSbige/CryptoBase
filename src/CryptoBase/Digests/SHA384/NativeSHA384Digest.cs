namespace CryptoBase.Digests.SHA384;

public class NativeSHA384Digest : IHash
{
	public string Name => @"SHA-384";
	public int Length => HashConstants.Sha384Length;
	public int BlockSize => HashConstants.Sha384BlockSize;

	private nuint _ptr;

	public NativeSHA384Digest()
	{
		_ptr = NativeMethods.sha384_new();
	}

	public unsafe void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptr = origin)
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sha384_update_final(_ptr, (nuint)ptr, (nuint)origin.Length, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public unsafe void Update(ReadOnlySpan<byte> source)
	{
		CheckIfDisposed();
		fixed (byte* ptr = source)
		{
			NativeMethods.sha384_update(_ptr, (nuint)ptr, (nuint)source.Length);
		}
	}

	public unsafe void GetHash(Span<byte> destination)
	{
		CheckIfDisposed();
		fixed (byte* ptrOut = destination)
		{
			NativeMethods.sha384_get_hash(_ptr, (nuint)ptrOut, (nuint)destination.Length);
		}
	}

	public void Reset()
	{
		CheckIfDisposed();
		NativeMethods.sha384_reset(_ptr);
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
		NativeMethods.sha384_dispose(_ptr);
		_ptr = default;
		GC.SuppressFinalize(this);
	}
}
