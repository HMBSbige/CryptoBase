using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Internal;

internal static class PlatformGuard
{
	[ModuleInitializer]
	[SuppressMessage("Usage", "CA2255:The ModuleInitializer attribute should not be used in libraries", Justification = "Runs once when the module loads and only checks the byte order.")]
	internal static void EnsureLittleEndian()
	{
		if (!BitConverter.IsLittleEndian)
		{
			throw new PlatformNotSupportedException("CryptoBase requires a little-endian platform.");
		}
	}
}
