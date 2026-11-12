using System.Reflection;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using AesArm = System.Runtime.Intrinsics.Arm.Aes;
using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.SpeedTest.Reporting;

/// <param name="InstructionSets">The instruction sets that matter to the library, and any environment variables that switch them off.</param>
internal sealed record EnvironmentSummary(string CryptoBaseVersion, string Runtime, string CodeGeneration, string OperatingSystem, Architecture Architecture, string? Cpu, int LogicalProcessorCount, ImmutableArray<string> InstructionSets)
{
	public static string CurrentCryptoBaseVersion { get; } = typeof(CpuIdUtils).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

	public static string CurrentCodeGeneration => RuntimeFeature.IsDynamicCodeCompiled ? "JIT" : "AOT";

	public static EnvironmentSummary Capture()
	{
		Architecture architecture = RuntimeInformation.ProcessArchitecture;
		bool x86 = architecture is Architecture.X86 or Architecture.X64;

		return new EnvironmentSummary
		(
			CurrentCryptoBaseVersion,
			RuntimeInformation.FrameworkDescription,
			CurrentCodeGeneration,
			RuntimeInformation.OSDescription,
			architecture,
			x86 ? CpuIdUtils.GetBrand().Trim() : null,
			Environment.ProcessorCount,
			[.. x86 ? GetX86InstructionSets() : GetArmInstructionSets(), .. GetInstructionSetSwitches()]
		);
	}

	private static IEnumerable<string> GetX86InstructionSets()
	{
		if (Avx512F.IsSupported)
		{
			List<string> parts = ["F"];
			AddIf(parts, Avx512BW.IsSupported, "BW");
			AddIf(parts, Avx512CD.IsSupported, "CD");
			AddIf(parts, Avx512DQ.IsSupported, "DQ");
			AddIf(parts, Avx512F.VL.IsSupported, "VL");
			AddIf(parts, Avx512Vbmi.IsSupported, "VBMI");
			AddIf(parts, Avx512Vbmi2.IsSupported, "VBMI2");
			yield return $"AVX-512({string.Join(',', parts)})";
		}
		else if (Avx2.IsSupported)
		{
			yield return "AVX2";
		}
		else if (Avx.IsSupported)
		{
			yield return "AVX";
		}
		else if (Sse41.IsSupported)
		{
			yield return "SSE4.1";
		}

		if (Avx10v2.IsSupported)
		{
			yield return "AVX10.2";
		}
		else if (Avx10v1.IsSupported)
		{
			yield return "AVX10.1";
		}

		if (AesX86.IsSupported)
		{
			yield return "AES";
		}

		if (Pclmulqdq.IsSupported)
		{
			yield return Pclmulqdq.V512.IsSupported ? "VPCLMULQDQ(512)" : Pclmulqdq.V256.IsSupported ? "VPCLMULQDQ(256)" : "PCLMULQDQ";
		}

		if (Gfni.IsSupported)
		{
			yield return Gfni.V512.IsSupported ? "GFNI(512)" : Gfni.V256.IsSupported ? "GFNI(256)" : "GFNI";
		}

		if (CpuIdUtils.IsSupportX86ShaEx())
		{
			yield return "SHA";
		}

		if (Bmi2.IsSupported)
		{
			yield return "BMI2";
		}

		yield return $"Vector{GetVectorWidth()}";
	}

	private static IEnumerable<string> GetArmInstructionSets()
	{
		if (AdvSimd.IsSupported)
		{
			yield return "AdvSimd";
		}

		if (AesArm.IsSupported)
		{
			yield return "AES";
		}

		if (Sha1.IsSupported)
		{
			yield return "SHA1";
		}

		if (Sha256.IsSupported)
		{
			yield return "SHA256";
		}

#if NET11_0_OR_GREATER
		if (Sha3.IsSupported)
		{
			yield return "SHA3";
		}
#endif

		if (Crc32.IsSupported)
		{
			yield return "CRC32";
		}

		yield return $"Vector{GetVectorWidth()}";
	}

	private static int GetVectorWidth()
	{
		return Vector512.IsHardwareAccelerated ? 512 : Vector256.IsHardwareAccelerated ? 256 : Vector128.IsHardwareAccelerated ? 128 : 64;
	}

	/// <summary>
	/// Gets the environment variables that turn instruction sets off or narrow the vectors, which change every result.
	/// </summary>
	private static IEnumerable<string> GetInstructionSetSwitches()
	{
		foreach (string name in Environment.GetEnvironmentVariables().Keys.Cast<string>().Order(StringComparer.Ordinal))
		{
			if (name.StartsWith("DOTNET_Enable", StringComparison.Ordinal)
				|| name.StartsWith("COMPlus_Enable", StringComparison.Ordinal)
				|| name.EndsWith("PreferredVectorBitWidth", StringComparison.Ordinal)
				|| name.EndsWith("MaxVectorTBitWidth", StringComparison.Ordinal))
			{
				yield return $"{name}={Environment.GetEnvironmentVariable(name)}";
			}
		}
	}

	private static void AddIf(List<string> list, bool condition, string value)
	{
		if (condition)
		{
			list.Add(value);
		}
	}
}
