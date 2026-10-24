using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.Abstractions.Kems;
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Tests.KeyAgreements;
using CryptoBase.Tests.Kems;
using CryptoBase.Tests.Signatures;
using System.Reflection;

namespace CryptoBase.Tests;

// The contract tests list their types by hand, so this catches a public implementation left out of them. The per-type data that they read needs no check here: a listed type that lacks it fails the contract tests.
public class ContractRegistrationTest
{
	[Test]
	[Arguments(typeof(ISignatureKey<>), typeof(SignatureKeyContractTest))]
	[Arguments(typeof(IKeyAgreement<>), typeof(KeyAgreementContractTest))]
	[Arguments(typeof(IKem<>), typeof(KemContractTest))]
	public async Task EveryPublicImplementationIsListed(Type contract, Type contractTest)
	{
		Type[] implementations = [.. LibraryAssemblies().SelectMany(static assembly => assembly.GetExportedTypes()).Where(type => type is { IsClass: true, IsAbstract: false } && type.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == contract))];
		MethodInfo[] tests = [.. contractTest.GetMethods().Where(static method => method.IsGenericMethodDefinition && method.IsDefined(typeof(TestAttribute)))];

		using (Assert.Multiple())
		{
			await Assert.That(implementations).IsNotEmpty();
			await Assert.That(tests).IsNotEmpty();

			foreach (MethodInfo test in tests)
			{
				Type[] listed = [.. test.GetCustomAttributes<GenerateGenericTestAttribute>().Select(static attribute => attribute.TypeArguments.Single())];
				await Assert.That(listed).IsEquivalentTo(implementations).Because(test.Name);
			}
		}
	}

	private static IEnumerable<Assembly> LibraryAssemblies()
	{
		return typeof(ContractRegistrationTest).Assembly.GetReferencedAssemblies().Where(static name => name.Name?.StartsWith("CryptoBase", StringComparison.Ordinal) is true).Select(System.Reflection.Assembly.Load);
	}
}
