using CryptoBase.Tests;
using System.Runtime.CompilerServices;

[assembly: ClassGenericArgumentsDisplayName]

namespace CryptoBase.Tests;

public sealed class ClassGenericArgumentsDisplayNameAttribute : DisplayNameFormatterAttribute
{
	protected override string FormatDisplayName(DiscoveredTestContext context)
	{
		string displayName = context.GetDisplayName();
		Type[] typeArguments = context.TestDetails.ClassType.GenericTypeArguments;

		if (typeArguments.Length is 0)
		{
			return displayName;
		}

		DefaultInterpolatedStringHandler handler = new(0, 0, null, stackalloc char[256]);
		handler.AppendFormatted(displayName);
		handler.AppendLiteral(" [");
		AppendTypeNames(ref handler, typeArguments);
		handler.AppendLiteral("]");
		return handler.ToStringAndClear();
	}

	private static void AppendTypeNames(ref DefaultInterpolatedStringHandler handler, Type[] types)
	{
		for (int i = 0; i < types.Length; ++i)
		{
			if (i > 0)
			{
				handler.AppendLiteral(", ");
			}

			AppendTypeName(ref handler, types[i]);
		}
	}

	private static void AppendTypeName(ref DefaultInterpolatedStringHandler handler, Type type)
	{
		string name = type.Name;
		int arityStart = name.IndexOf('`');

		if (arityStart < 0)
		{
			handler.AppendFormatted(name);
			return;
		}

		handler.AppendFormatted(name.AsSpan(0, arityStart));
		handler.AppendLiteral("<");
		AppendTypeNames(ref handler, type.GetGenericArguments());
		handler.AppendLiteral(">");
	}
}
