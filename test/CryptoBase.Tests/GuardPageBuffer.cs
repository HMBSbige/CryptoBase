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
	// What GetCurrentProcess returns.
	private const nint CurrentProcess = -1;

	private const int ProtNone = 0;
	private const int ProtRead = 1;
	private const int ProtWrite = 2;
	private const int MapPrivate = 0x02;
	private const int MadvNoHugePage = 15;

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

		// Without huge pages, touching a page does not bring in its neighbors. A kernel without them rejects the advice.
		if (OperatingSystem.IsLinux())
		{
			_ = AdviseMemory(_allocation, _allocationSize, MadvNoHugePage);
		}
	}

	public Span<byte> Span => new(_allocation + _guardOffset - (nuint)_length, _length);

	// For each page that holds part of Span, whether code has read or written it.
	public bool[] GetResidency()
	{
		nuint pageSize = (nuint)Environment.SystemPageSize;
		nuint end = (nuint)(_allocation + _guardOffset);
		nuint start = end - (nuint)_length & ~(pageSize - 1);
		bool[] residency = new bool[(end - start) / pageSize];

		for (int i = 0; i < residency.Length; ++i)
		{
			nuint page = start + (nuint)i * pageSize;
			residency[i] = OperatingSystem.IsWindows() ? IsInWorkingSet(page) : IsInCore(page, pageSize);
		}

		return residency;
	}

	// The lowest bit of the attributes, Valid, is set for a page in the working set.
	private static bool IsInWorkingSet(nuint page)
	{
		WorkingSetExInformation information = new(page, 0);

		if (!QueryWorkingSetEx(CurrentProcess, &information, (uint)sizeof(WorkingSetExInformation)))
		{
			throw new InvalidOperationException($"QueryWorkingSetEx failed with error {Marshal.GetLastPInvokeError()}.");
		}

		return (information.VirtualAttributes & 1) is not 0;
	}

	// The lowest bit of the status is set for a resident page.
	private static bool IsInCore(nuint page, nuint pageSize)
	{
		byte status;

		if (QueryResidency((void*)page, pageSize, &status) is not 0)
		{
			throw new InvalidOperationException($"mincore failed with errno {Marshal.GetLastPInvokeError()}.");
		}

		return (status & 1) is not 0;
	}

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

	[LibraryImport("kernel32", EntryPoint = "K32QueryWorkingSetEx", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static partial bool QueryWorkingSetEx(nint process, WorkingSetExInformation* information, uint length);

	[LibraryImport("libc", EntryPoint = "madvise", SetLastError = true)]
	private static partial int AdviseMemory(void* address, nuint length, int advice);

	[LibraryImport("libc", EntryPoint = "mincore", SetLastError = true)]
	private static partial int QueryResidency(void* address, nuint length, byte* vector);

	// PSAPI_WORKING_SET_EX_INFORMATION.
	private readonly record struct WorkingSetExInformation(nuint VirtualAddress, nuint VirtualAttributes);
}
