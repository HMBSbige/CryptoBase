namespace CryptoBase.Internal;

/// <summary>
/// Calls getrandom directly on Linux, and falls back to <see cref="RandomNumberGenerator"/> elsewhere.
/// </summary>
internal static partial class SystemRandom
{
	private const int EPERM = 1;
	private const int EINTR = 4;
	private const int ENOSYS = 38;
	private const uint GRND_NONBLOCK = 1;

	internal static bool UsesGetRandom { get; } = OperatingSystem.IsLinux() && ProbeGetRandom();

	internal static void Fill(Span<byte> data)
	{
		if (!UsesGetRandom)
		{
			RandomNumberGenerator.Fill(data);
			return;
		}

		// No flags: block until the pool is ready.
		while (!data.IsEmpty)
		{
			nint n = GetRandom(data, (nuint)data.Length, 0);

			if (n >= 0)
			{
				data = data.Slice((int)n);
				continue;
			}

			int errno = Marshal.GetLastPInvokeError();

			if (errno is not EINTR)
			{
				throw new CryptographicException($"getrandom failed with errno {errno}.");
			}
		}
	}

	private static bool ProbeGetRandom()
	{
		try
		{
			// EAGAIN before the pool is ready still means the system call exists.
			return GetRandom(default, 0, GRND_NONBLOCK) >= 0 || Marshal.GetLastPInvokeError() is not (ENOSYS or EPERM);
		}
		catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
		{
			return false;
		}
	}

	[LibraryImport("libc", EntryPoint = "getrandom", SetLastError = true)]
	private static partial nint GetRandom(Span<byte> buffer, nuint length, uint flags);
}
