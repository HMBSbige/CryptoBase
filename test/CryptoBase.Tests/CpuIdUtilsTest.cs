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
