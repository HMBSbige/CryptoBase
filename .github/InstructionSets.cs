#:property PublishAot=false

using System.Globalization;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

// .NET 10 has no public IsSupported property for VAES.
bool vaes = Aes.IsSupported && Avx.IsSupported && (X86Base.CpuId(7, 0).Ecx & 1 << 9) is not 0 && IsEnabled("VAES");

(string Name, bool Supported)[] features =
[
	("Vector128", Vector128.IsHardwareAccelerated),
	("Vector256", Vector256.IsHardwareAccelerated),
	("Vector512", Vector512.IsHardwareAccelerated),
	("SSE2", Sse2.IsSupported),
	("SSSE3", Ssse3.IsSupported),
	("SSE4.1", Sse41.IsSupported),
	("SSE4.2", Sse42.IsSupported),
	("AVX", Avx.IsSupported),
	("AVX2", Avx2.IsSupported),
	("AVX512F", Avx512F.IsSupported),
	("AVX512F.VL", Avx512F.VL.IsSupported),
	("AVX512BW", Avx512BW.IsSupported),
	("AVX512BW.VL", Avx512BW.VL.IsSupported),
	("AVX512DQ", Avx512DQ.IsSupported),
	("AVX512DQ.VL", Avx512DQ.VL.IsSupported),
	("AVX512VBMI", Avx512Vbmi.IsSupported),
	("AVX512VBMI.VL", Avx512Vbmi.VL.IsSupported),
	("AVX512VBMI2", Avx512Vbmi2.IsSupported),
	("AVX512VBMI2.VL", Avx512Vbmi2.VL.IsSupported),
	("AES", Aes.IsSupported),
	("VAES.V256", vaes),
	("VAES.V512", vaes && Avx512F.IsSupported),
	("GFNI", Gfni.IsSupported),
	("GFNI.V256", Gfni.V256.IsSupported),
	("GFNI.V512", Gfni.V512.IsSupported),
	("PCLMULQDQ", Pclmulqdq.IsSupported),
	("VPCLMULQDQ.V256", Pclmulqdq.V256.IsSupported),
	("VPCLMULQDQ.V512", Pclmulqdq.V512.IsSupported),
	("BMI1", Bmi1.IsSupported),
	("BMI2", Bmi2.IsSupported),
	("LZCNT", Lzcnt.IsSupported),
	("POPCNT", Popcnt.IsSupported)
];

foreach ((string name, bool _) in features.Where(static feature => feature.Supported).OrderBy(static feature => feature.Name, StringComparer.Ordinal))
{
	Console.WriteLine(name);
}

static bool IsEnabled(string instructionSet)
{
	string? value = Environment.GetEnvironmentVariable($"DOTNET_Enable{instructionSet}");
	if (string.IsNullOrEmpty(value))
	{
		value = Environment.GetEnvironmentVariable($"COMPlus_Enable{instructionSet}");
	}

	ReadOnlySpan<char> text = value.AsSpan().Trim();

	if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
	{
		text = text.Slice(2);
	}

	return !uint.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint enabled) || enabled is not 0;
}
