using CryptoBase.Platform;
using System.Reflection;

namespace CryptoBase.Tests.Platform;

public class PlatformTypesTest
{
	// A platform type must beat the managed implementation somewhere, using hardware .NET has no intrinsics for, as PlatformSha256 does. IsPreferredFor says where, by input length.
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
				MethodInfo? isPreferredFor = type.GetMethod("IsPreferredFor", BindingFlags.Public | BindingFlags.Static, [typeof(int)]);
				await Assert.That(isPreferredFor?.ReturnType).IsEqualTo(typeof(bool))
					.Because($"{type.Name} needs a static bool IsPreferredFor(int) that is true only where the platform beats the managed implementation for an input of that length; a type that is preferred nowhere does not belong in CryptoBase.Platform");
			}
		}
	}
}
