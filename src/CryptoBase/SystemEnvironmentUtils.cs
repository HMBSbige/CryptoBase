using System.Numerics;
using System.Reflection;
using AesArm = System.Runtime.Intrinsics.Arm.Aes;
using AesX86 = System.Runtime.Intrinsics.X86.Aes;
using Wasm = System.Runtime.Intrinsics.Wasm;

namespace CryptoBase;

/// <summary>Provides runtime and hardware intrinsic information.</summary>
public static class SystemEnvironmentUtils
{
	/// <summary>Gets the environment and instruction sets available to the current process.</summary>
	public static string GetEnvironmentInfo()
	{
		DefaultInterpolatedStringHandler handler = new();

		Append(ref handler, "OS", RuntimeInformation.OSDescription);
		Append(ref handler, "OS architecture", RuntimeInformation.OSArchitecture);
		Append(ref handler, "Process architecture", RuntimeInformation.ProcessArchitecture);
		Append(ref handler, "Runtime", RuntimeInformation.FrameworkDescription);
		Append(ref handler, "CryptoBase version", typeof(SystemEnvironmentUtils).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "Unknown");
		Append(ref handler, "Processor count", Environment.ProcessorCount);

		handler.AppendLiteral(Environment.NewLine);
		Append(ref handler, "Vector<byte>.Count", Vector<byte>.Count);
		Append(ref handler, "Vector.IsHardwareAccelerated", Vector.IsHardwareAccelerated);
		Append(ref handler, "Vector64.IsHardwareAccelerated", Vector64.IsHardwareAccelerated);
		Append(ref handler, "Vector128.IsHardwareAccelerated", Vector128.IsHardwareAccelerated);
		Append(ref handler, "Vector256.IsHardwareAccelerated", Vector256.IsHardwareAccelerated);
		Append(ref handler, "Vector512.IsHardwareAccelerated", Vector512.IsHardwareAccelerated);

		switch (RuntimeInformation.ProcessArchitecture)
		{
			case Architecture.X86 or Architecture.X64:
			{
				handler.AppendLiteral(Environment.NewLine);
				Append(ref handler, "CPU vendor", CpuIdUtils.GetVendor());
				Append(ref handler, "CPU brand", CpuIdUtils.GetBrand());
				AppendX86(ref handler);
				break;
			}
			case Architecture.Arm or Architecture.Arm64:
			{
				AppendArm(ref handler);
				break;
			}
			case Architecture.Wasm:
			{
				handler.AppendLiteral(Environment.NewLine);
				Append(ref handler, "Wasm.PackedSimd", Wasm.PackedSimd.IsSupported);
				break;
			}
		}

		AppendInstructionSetSwitches(ref handler);
		return handler.ToStringAndClear();
	}

	private static void AppendX86(ref DefaultInterpolatedStringHandler handler)
	{
		handler.AppendLiteral(Environment.NewLine);
		Append(ref handler, "X86.Aes", AesX86.IsSupported);
		Append(ref handler, "X86.Avx", Avx.IsSupported);
		Append(ref handler, "X86.Avx10v1", Avx10v1.IsSupported);
		Append(ref handler, "X86.Avx10v1.V512", Avx10v1.V512.IsSupported);
		Append(ref handler, "X86.Avx10v2", Avx10v2.IsSupported);
		Append(ref handler, "X86.Avx10v2.V512", Avx10v2.V512.IsSupported);
		Append(ref handler, "X86.Avx2", Avx2.IsSupported);
		Append(ref handler, "X86.Avx512BW", Avx512BW.IsSupported);
		Append(ref handler, "X86.Avx512BW.VL", Avx512BW.VL.IsSupported);
		Append(ref handler, "X86.Avx512CD", Avx512CD.IsSupported);
		Append(ref handler, "X86.Avx512CD.VL", Avx512CD.VL.IsSupported);
		Append(ref handler, "X86.Avx512DQ", Avx512DQ.IsSupported);
		Append(ref handler, "X86.Avx512DQ.VL", Avx512DQ.VL.IsSupported);
		Append(ref handler, "X86.Avx512F", Avx512F.IsSupported);
		Append(ref handler, "X86.Avx512F.VL", Avx512F.VL.IsSupported);
		Append(ref handler, "X86.Avx512Vbmi", Avx512Vbmi.IsSupported);
		Append(ref handler, "X86.Avx512Vbmi.VL", Avx512Vbmi.VL.IsSupported);
		Append(ref handler, "X86.Avx512Vbmi2", Avx512Vbmi2.IsSupported);
		Append(ref handler, "X86.Avx512Vbmi2.VL", Avx512Vbmi2.VL.IsSupported);
		Append(ref handler, "X86.AvxVnni", AvxVnni.IsSupported);
		Append(ref handler, "X86.AvxVnniInt16", AvxVnniInt16.IsSupported);
		Append(ref handler, "X86.AvxVnniInt16.V512", AvxVnniInt16.V512.IsSupported);
		Append(ref handler, "X86.AvxVnniInt8", AvxVnniInt8.IsSupported);
		Append(ref handler, "X86.AvxVnniInt8.V512", AvxVnniInt8.V512.IsSupported);
		Append(ref handler, "X86.Bmi1", Bmi1.IsSupported);
		Append(ref handler, "X86.Bmi2", Bmi2.IsSupported);
		Append(ref handler, "X86.Fma", Fma.IsSupported);
		Append(ref handler, "X86.Gfni", Gfni.IsSupported);
		Append(ref handler, "X86.Gfni.V256", Gfni.V256.IsSupported);
		Append(ref handler, "X86.Gfni.V512", Gfni.V512.IsSupported);
		Append(ref handler, "X86.Lzcnt", Lzcnt.IsSupported);
		Append(ref handler, "X86.Pclmulqdq", Pclmulqdq.IsSupported);
		Append(ref handler, "X86.Pclmulqdq.V256", Pclmulqdq.V256.IsSupported);
		Append(ref handler, "X86.Pclmulqdq.V512", Pclmulqdq.V512.IsSupported);
		Append(ref handler, "X86.Popcnt", Popcnt.IsSupported);
		Append(ref handler, "X86.Sse", Sse.IsSupported);
		Append(ref handler, "X86.Sse2", Sse2.IsSupported);
		Append(ref handler, "X86.Sse3", Sse3.IsSupported);
		Append(ref handler, "X86.Sse41", Sse41.IsSupported);
		Append(ref handler, "X86.Sse42", Sse42.IsSupported);
		Append(ref handler, "X86.Ssse3", Ssse3.IsSupported);
		Append(ref handler, "X86.X86Base", X86Base.IsSupported);
		Append(ref handler, "X86.X86Serialize", X86Serialize.IsSupported);
	}

	private static void AppendArm(ref DefaultInterpolatedStringHandler handler)
	{
		handler.AppendLiteral(Environment.NewLine);
		Append(ref handler, "Arm.AdvSimd", AdvSimd.IsSupported);
		Append(ref handler, "Arm.Aes", AesArm.IsSupported);
		Append(ref handler, "Arm.ArmBase", ArmBase.IsSupported);
		Append(ref handler, "Arm.Crc32", Crc32.IsSupported);
		Append(ref handler, "Arm.Dp", Dp.IsSupported);
		Append(ref handler, "Arm.Rdm", Rdm.IsSupported);
		Append(ref handler, "Arm.Sha1", Sha1.IsSupported);
		Append(ref handler, "Arm.Sha256", Sha256.IsSupported);
	}

	private static void AppendInstructionSetSwitches(ref DefaultInterpolatedStringHandler handler)
	{
		string[] switches = Environment.GetEnvironmentVariables().Keys.Cast<string>()
			.Where
			(static name => name.StartsWith("DOTNET_Enable", StringComparison.Ordinal)
							|| name.StartsWith("COMPlus_Enable", StringComparison.Ordinal)
							|| name is "DOTNET_PreferredVectorBitWidth" or "COMPlus_PreferredVectorBitWidth" or "DOTNET_MaxVectorTBitWidth" or "COMPlus_MaxVectorTBitWidth"
			)
			.Order(StringComparer.Ordinal)
			.ToArray();

		if (switches.Length is 0)
		{
			return;
		}

		handler.AppendLiteral(Environment.NewLine);

		foreach (string name in switches)
		{
			Append(ref handler, name, Environment.GetEnvironmentVariable(name));
		}
	}

	private static void Append<T>(ref DefaultInterpolatedStringHandler handler, string name, T value)
	{
		handler.AppendFormatted(name, -34);
		handler.AppendLiteral(": ");
		handler.AppendFormatted(value);
		handler.AppendLiteral(Environment.NewLine);
	}
}
