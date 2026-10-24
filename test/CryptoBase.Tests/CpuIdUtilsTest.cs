using System.Buffers.Binary;
using System.Runtime.Intrinsics.X86;
using System.Text;

namespace CryptoBase.Tests;

public class CpuIdUtilsTest
{
	[Test]
	[Arguments(0x00B40F40, 0x1A, 0x44)] // AMD Zen 5 (Granite Ridge)
	[Arguments(0x00050654, 6, 0x55)] // Intel Skylake-X
	[Arguments(0x00010543, 5, 4)] // Extended model applies only to families 6 and 0Fh
	public async Task DecodesDisplayFamilyAndModel(int signature, int family, int model)
	{
		await Assert.That(CpuIdUtils.DecodeFamilyAndModel(signature)).IsEqualTo((family, model));
	}

	[Test]
	[Arguments(0x1A, 0x00, true)]
	[Arguments(0x1A, 0x2F, true)]
	[Arguments(0x1A, 0x30, false)]
	[Arguments(0x1A, 0x40, true)]
	[Arguments(0x1A, 0x4F, true)]
	[Arguments(0x1A, 0x50, false)]
	[Arguments(0x1A, 0x5F, false)]
	[Arguments(0x1A, 0x60, true)]
	[Arguments(0x1A, 0x7F, true)]
	[Arguments(0x1A, 0x80, false)]
	[Arguments(0x1A, 0xCF, false)]
	[Arguments(0x1A, 0xD0, true)]
	[Arguments(0x1A, 0xD7, true)]
	[Arguments(0x1A, 0xD8, false)]
	[Arguments(0x19, 0x44, false)]
	public async Task MatchesZen5ModelRanges(int family, int model, bool expected)
	{
		await Assert.That(CpuIdUtils.IsZen5(family, model)).IsEqualTo(expected);
	}

	[Test]
	[Arguments(0x1A, 0x00, true)]
	[Arguments(0x1A, 0x1F, true)]
	[Arguments(0x1A, 0x20, false)] // Strix Point
	[Arguments(0x1A, 0x24, false)]
	[Arguments(0x1A, 0x40, true)] // Granite Ridge
	[Arguments(0x1A, 0x44, true)]
	[Arguments(0x1A, 0x4F, true)]
	[Arguments(0x1A, 0x60, false)] // Krackan
	[Arguments(0x1A, 0x6F, false)]
	[Arguments(0x1A, 0x70, true)] // Strix Halo
	[Arguments(0x1A, 0x7F, true)]
	[Arguments(0x1A, 0x80, false)]
	[Arguments(0x1A, 0xD0, false)]
	[Arguments(0x19, 0x11, false)]
	public async Task MatchesZen5With512BitDatapathModelRanges(int family, int model, bool expected)
	{
		await Assert.That(CpuIdUtils.IsZen5With512BitDatapath(family, model)).IsEqualTo(expected);
	}

	[Test]
	[Arguments(0x19, 0x01, true)] // Milan
	[Arguments(0x19, 0x11, true)] // Genoa
	[Arguments(0x19, 0x61, true)] // Raphael
	[Arguments(0x19, 0x74, true)] // Phoenix
	[Arguments(0x1A, 0x1F, false)]
	[Arguments(0x1A, 0x20, true)] // Strix Point
	[Arguments(0x1A, 0x2F, true)]
	[Arguments(0x1A, 0x30, false)]
	[Arguments(0x1A, 0x44, false)] // Granite Ridge
	[Arguments(0x1A, 0x60, true)] // Krackan
	[Arguments(0x1A, 0x6F, true)]
	[Arguments(0x1A, 0x70, false)] // Strix Halo
	[Arguments(0x1A, 0xD0, false)]
	[Arguments(0x17, 0x71, false)] // Zen 2
	public async Task MatchesZenWith256BitDatapathModelRanges(int family, int model, bool expected)
	{
		await Assert.That(CpuIdUtils.IsZenWith256BitDatapath(family, model)).IsEqualTo(expected);
	}

	[Test]
	[Arguments("AuthenticAMD", true)]
	[Arguments("GenuineIntel", false)]
	[Arguments("HygonGenuine", false)]
	public async Task RecognizesAmdVendorRegisters(string vendor, bool expected)
	{
		byte[] bytes = Encoding.ASCII.GetBytes(vendor);
		int ebx = BinaryPrimitives.ReadInt32LittleEndian(bytes);
		int edx = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4));
		int ecx = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8));

		await Assert.That(CpuIdUtils.IsAuthenticAmd((0, ebx, ecx, edx))).IsEqualTo(expected);
	}

	[Test]
	public async Task AmdVendorRegistersAgreeWithVendorString()
	{
		bool amd = X86Base.IsSupported && CpuIdUtils.IsAuthenticAmd(X86Base.CpuId(0, 0));

		await Assert.That(amd).IsEqualTo(CpuIdUtils.GetVendor() is "AuthenticAMD");
	}
}
