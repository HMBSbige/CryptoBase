namespace CryptoBase.Ciphers.Modes;

/// <summary>Provides XTS tweak encoding.</summary>
public static class XtsMode
{
	/// <summary>Writes the data-unit number as a little-endian tweak.</summary>
	public static void GetTweak(Span<byte> tweak, UInt128 dataUnitNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(tweak, dataUnitNumber);
	}
}
