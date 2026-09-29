namespace CryptoBase.Ciphers.Modes;

/// <summary>Provides XTS tweak encoding.</summary>
public static class XtsMode
{
	/// <summary>Writes the data-unit number as a little-endian tweak.</summary>
	public static void GetIV(Span<byte> iv, UInt128 dataUnitSeqNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(iv, dataUnitSeqNumber);
	}
}
