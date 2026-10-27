namespace CryptoBase.Tests.Cavp;

// Supplies each record of an embedded CAVP response file as test data.
public sealed class CavpRecordsAttribute(string fileName) : DataSourceGeneratorAttribute<CavpRecord>
{
	protected override IEnumerable<Func<CavpRecord>> GenerateDataSources(DataGeneratorMetadata dataGeneratorMetadata)
	{
		foreach (CavpRecord record in CavpRspFile.Load(fileName).Records)
		{
			yield return () => record;
		}
	}
}
