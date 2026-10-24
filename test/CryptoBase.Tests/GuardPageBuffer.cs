using System.Runtime.InteropServices;

namespace CryptoBase.Tests;

// Memory that ends where an inaccessible page begins, so code that reads or writes past the end of Span faults instead of touching whatever happens to follow it.
public sealed unsafe partial class GuardPageBuffer : IDisposable
{
	private const uint MemCommit = 0x1000;
	private const uint MemReserve = 0x2000;
	private const uint MemRelease = 0x8000;
	private const uint PageNoAccess = 0x01;
	private const uint PageReadWrite = 0x04;

	private const int ProtNone = 0;
	private const int ProtRead = 1;
	private const int ProtWrite = 2;
	private const int MapPrivate = 0x02;

	private readonly byte* _allocation;
	private readonly nuint _allocationSize;
	private readonly nuint _guardOffset;
	private readonly int _length;

	public static bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

	public static void SkipUnlessSupported()
	{
		if (!IsSupported)
		{
			Skip.Test("Guard pages are not supported here.");
		}
	}

	public GuardPageBuffer(int length)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(length);

		nuint pageSize = (nuint)Environment.SystemPageSize;
		_guardOffset = ((nuint)length + pageSize - 1) / pageSize * pageSize;
		_allocationSize = _guardOffset + pageSize;
		_length = length;

		if (OperatingSystem.IsWindows())
		{
			_allocation = (byte*)VirtualAlloc(null, _allocationSize, MemCommit | MemReserve, PageReadWrite);

			if (_allocation is null)
			{
				throw new InvalidOperationException($"VirtualAlloc failed with error {Marshal.GetLastPInvokeError()}.");
			}

			if (!VirtualProtect(_allocation + _guardOffset, pageSize, PageNoAccess, out _))
			{
				int error = Marshal.GetLastPInvokeError();
				VirtualFree(_allocation, 0, MemRelease);
				throw new InvalidOperationException($"VirtualProtect failed with error {error}.");
			}

			return;
		}

		int mapAnonymous = OperatingSystem.IsMacOS() ? 0x1000 : 0x20;
		_allocation = (byte*)MapMemory(null, _allocationSize, ProtRead | ProtWrite, MapPrivate | mapAnonymous, -1, 0);

		if (_allocation == (byte*)-1)
		{
			throw new InvalidOperationException($"mmap failed with errno {Marshal.GetLastPInvokeError()}.");
		}

		if (ProtectMemory(_allocation + _guardOffset, pageSize, ProtNone) is not 0)
		{
			int error = Marshal.GetLastPInvokeError();
			UnmapMemory(_allocation, _allocationSize);
			throw new InvalidOperationException($"mprotect failed with errno {error}.");
		}
	}

	public Span<byte> Span => new(_allocation + _guardOffset - (nuint)_length, _length);

	public void Dispose()
	{
		if (OperatingSystem.IsWindows())
		{
			VirtualFree(_allocation, 0, MemRelease);
		}
		else
		{
			UnmapMemory(_allocation, _allocationSize);
		}
	}

	[LibraryImport("kernel32", SetLastError = true)]
	private static partial void* VirtualAlloc(void* address, nuint size, uint allocationType, uint protection);

	[LibraryImport("kernel32", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static partial bool VirtualProtect(void* address, nuint size, uint protection, out uint oldProtection);

	[LibraryImport("kernel32", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static partial bool VirtualFree(void* address, nuint size, uint freeType);

	[LibraryImport("libc", EntryPoint = "mmap", SetLastError = true)]
	private static partial void* MapMemory(void* address, nuint length, int protection, int flags, int fileDescriptor, nint offset);

	[LibraryImport("libc", EntryPoint = "mprotect", SetLastError = true)]
	private static partial int ProtectMemory(void* address, nuint length, int protection);

	[LibraryImport("libc", EntryPoint = "munmap", SetLastError = true)]
	private static partial int UnmapMemory(void* address, nuint length);
}
