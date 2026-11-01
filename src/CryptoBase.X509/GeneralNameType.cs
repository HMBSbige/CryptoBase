namespace CryptoBase.X509;

// The alternatives of GeneralName (RFC 5280, Sec. 4.2.1.6), numbered as their context-specific tags.
internal enum GeneralNameType
{
	OtherName = 0,
	Rfc822Name = 1,
	DnsName = 2,
	X400Address = 3,
	DirectoryName = 4,
	EdiPartyName = 5,
	UniformResourceIdentifier = 6,
	IPAddress = 7,
	RegisteredId = 8
}
