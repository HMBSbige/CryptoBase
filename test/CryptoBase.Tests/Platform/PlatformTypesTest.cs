using CryptoBase.Platform;
using System.Reflection;

namespace CryptoBase.Tests.Platform;

public class PlatformTypesTest
{
	// A platform type must beat the managed implementation on some processor, using hardware .NET has no intrinsics
	// for, as PlatformSha256 does. IsPreferred names those processors.
	[Test]
	public async Task EveryPlatformTypeSaysWhereItIsPreferred()
	{
		Type[] types = typeof(PlatformSha256).Assembly.GetTypes()
			.Where(static type => type is { IsPublic: true, Namespace: "CryptoBase.Platform" })
			.OrderBy(static type => type.FullName, StringComparer.Ordinal)
			.ToArray();
		await Assert.That(types).IsNotEmpty();

		using (Assert.Multiple())
		{
			foreach (Type type in types)
			{
				PropertyInfo? isPreferred = type.GetProperty("IsPreferred", BindingFlags.Public | BindingFlags.Static);
				await Assert.That(isPreferred?.PropertyType).IsEqualTo(typeof(bool))
					.Because($"{type.Name} needs a static bool IsPreferred that is true only on the processors where the platform beats the managed implementation; a type that is preferred nowhere does not belong in CryptoBase.Platform");
			}
		}
	}
}
