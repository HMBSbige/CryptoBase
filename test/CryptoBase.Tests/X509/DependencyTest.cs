using CryptoBase.X509;

namespace CryptoBase.Tests.X509;

// The package takes keys as ISignatureKey, so it references CryptoBase.Abstractions and the BCL, and the caller chooses the implementations.
public class DependencyTest
{
	[Test]
	public async Task ReferencesOnlyTheAbstractionsAndTheBcl()
	{
		string[] references = [.. typeof(Certificate).Assembly.GetReferencedAssemblies().Select(static name => name.Name ?? "")];

		using (Assert.Multiple())
		{
			await Assert.That(references).Contains("CryptoBase.Abstractions");
			await Assert.That(references).All(static name => name is "CryptoBase.Abstractions" || name.StartsWith("System.", StringComparison.Ordinal)).Because(string.Join(", ", references));
		}
	}
}
