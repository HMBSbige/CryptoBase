namespace CryptoBase.Kems.MLKem;

// A parameter set of FIPS 203, Table 2, as a struct so that MLKemKey folds its sizes into constants.
internal interface IMLKemParameters
{
	static abstract int K { get; }

	static abstract int Eta1 { get; }

	static abstract int Du { get; }

	static abstract int Dv { get; }
}
