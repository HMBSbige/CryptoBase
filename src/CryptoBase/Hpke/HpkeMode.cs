namespace CryptoBase.Hpke;

// The modes of RFC 9180, Section 5, by their identifiers.
internal enum HpkeMode : byte
{
	Base = 0x00,
	Psk = 0x01,
	Auth = 0x02,
	AuthPsk = 0x03
}
