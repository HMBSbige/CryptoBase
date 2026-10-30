using CryptoBase.EllipticCurves;

namespace CryptoBase.Tests.EllipticCurves;

// Each table ends at a guard page, so a read past the last entry faults.
public class MaskedSelectTest
{
	private static readonly int[] Counts = [1, 2, 3, 15, 16, 17, 32, 33, 64];

	[Test]
	public async Task EveryWidthIsListed()
	{
		Type[] widths = [.. typeof(ILimbVector<>).Assembly.GetTypes().Where(static type => type.GetInterfaces().Any(static i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ILimbVector<>)))];

		await Assert.That(LookupCase.WidthTypes()).IsEquivalentTo(widths);
	}

	[Test]
	[MethodDataSource(typeof(LookupCase), nameof(LookupCase.All))]
	public async Task LookupGivesTheEntryAtTheIndex(LookupCase lookup)
	{
		GuardPageBuffer.SkipUnlessSupported();

		Random random = new(1);
		List<string> failures = [];

		foreach (int count in Counts)
		{
			using GuardPageBuffer table = new(count * lookup.EntryLength);
			random.NextBytes(table.Span);
			byte[] zero = new byte[lookup.EntryLength];

			foreach (uint index in Enumerable.Range(0, count + 2).Select(static index => (uint)index).Append(1u << 31).Append(uint.MaxValue))
			{
				ReadOnlySpan<byte> expected = index < count ? table.Span.Slice((int)index * lookup.EntryLength, lookup.EntryLength) : zero;

				foreach (byte filler in (byte[])[0x00, 0xFF])
				{
					byte[] actual = lookup.Lookup(table.Span, count, index, filler);

					if (!expected.SequenceEqual(actual))
					{
						failures.Add($"{count} entries, index {index}, filler {filler:X2}: {Convert.ToHexString(actual)}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A page of a new table becomes resident only when read. The table spans two pages or more, so index 0 selects nothing in the last, and count selects nothing at all.
	[Test]
	[MethodDataSource(typeof(LookupCase), nameof(LookupCase.All))]
	public async Task LookupReadsEveryEntry(LookupCase lookup)
	{
		GuardPageBuffer.SkipUnlessSupported();

		int count = (2 * Environment.SystemPageSize + lookup.EntryLength - 1) / lookup.EntryLength;

		foreach (uint index in (uint[])[0, (uint)count])
		{
			using GuardPageBuffer table = new(count * lookup.EntryLength);
			await Assert.That(table.GetResidency()).DoesNotContain(true);
			lookup.Lookup(table.Span, count, index, 0x00);
			await Assert.That(table.GetResidency()).DoesNotContain(false);
		}
	}
}
