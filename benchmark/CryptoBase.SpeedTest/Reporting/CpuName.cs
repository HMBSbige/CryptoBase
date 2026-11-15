using Microsoft.Win32;
using System.Runtime.Versioning;

namespace CryptoBase.SpeedTest.Reporting;

/// <summary>
/// Gets the name of the processor: the CPUID brand string on x86, and elsewhere what the operating system reports, since Arm has no instruction that returns one.
/// </summary>
internal static class CpuName
{
	private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

	public static string? Get()
	{
		if (RuntimeInformation.ProcessArchitecture is Architecture.X86 or Architecture.X64)
		{
			// GetBrand returns "Unknown" where the processor lacks the brand string leaves.
			string? brand = Normalize(CpuIdUtils.GetBrand());
			return brand is "Unknown" ? null : brand;
		}

		try
		{
			if (OperatingSystem.IsMacOS())
			{
				return Normalize(Run("sysctl", ["-n", "machdep.cpu.brand_string"])?.FirstOrDefault());
			}

			if (OperatingSystem.IsWindows())
			{
				return Normalize(GetWindowsName());
			}

			if (OperatingSystem.IsLinux())
			{
				return Normalize(GetLinuxName());
			}
		}
		catch (Exception)
		{
			// The name only labels the results; report it as unknown where the system does not give it.
		}

		return null;
	}

	[SupportedOSPlatform("windows")]
	private static string? GetWindowsName()
	{
		using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
		return key?.GetValue("ProcessorNameString") as string;
	}

	/// <summary>
	/// Arm kernels seldom write a model name into /proc/cpuinfo, only the implementer and part numbers; lscpu turns those into a name from its own table.
	/// </summary>
	private static string? GetLinuxName()
	{
		const string cpuInfoKey = "model name";
		const string lscpuKey = "Model name";

		string? name = File.ReadLines("/proc/cpuinfo").Select(static line => GetValue(line, cpuInfoKey)).FirstOrDefault(static value => value is not null);

		if (name is not null)
		{
			return name;
		}

		// lscpu translates its headings to the locale, so it runs in the C locale.
		List<string>? lscpu = Run("lscpu", [], [("LC_ALL", "C"), ("LANG", "C"), ("LANGUAGE", "C")]);
		return lscpu?.Select(static line => GetValue(line, lscpuKey)).FirstOrDefault(static value => value is not null);
	}

	private static string? GetValue(string line, string key)
	{
		int colon = line.IndexOf(':');

		if (colon < 0 || !line.AsSpan(0, colon).Trim().SequenceEqual(key))
		{
			return null;
		}

		return line.Substring(colon + 1).Trim();
	}

	private static List<string>? Run(string fileName, string[] arguments, (string Name, string Value)[]? environment = null)
	{
		using Process process = new();
		process.StartInfo = new ProcessStartInfo(fileName, arguments)
		{
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			UseShellExecute = false
		};

		foreach ((string name, string value) in environment ?? [])
		{
			process.StartInfo.Environment[name] = value;
		}

		List<string> lines = [];
		process.OutputDataReceived += (_, e) =>
		{
			if (e.Data is not null)
			{
				lines.Add(e.Data);
			}
		};

		process.Start();
		process.BeginOutputReadLine();
		// Without a handler, the errors are read and dropped, so they stay out of the report and cannot fill the pipe.
		process.BeginErrorReadLine();

		if (!process.WaitForExit(CommandTimeout))
		{
			process.Kill(entireProcessTree: true);
			return null;
		}

		// The wait without a timeout returns once both streams have been read to their ends.
		process.WaitForExit();
		return process.ExitCode is 0 ? lines : null;
	}

	private static string? Normalize(string? name)
	{
		string? trimmed = name?.Trim('\0', ' ', '\t', '\r', '\n');
		return string.IsNullOrEmpty(trimmed) ? null : trimmed;
	}
}
