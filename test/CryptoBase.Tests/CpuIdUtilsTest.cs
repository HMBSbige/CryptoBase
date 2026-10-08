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
}
