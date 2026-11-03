namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The digit size of a kernel, as a type so that shifts and masks are constants in its code. Code that uses them takes Bits into locals and derives the masks and shifts there: a property that derives them does not always inline without a profile, and then stays a call at every use.
internal interface IRadix
{
	static abstract int Bits { get; }
}

internal readonly struct Radix57 : IRadix
{
	public static int Bits => 57;
}

internal readonly struct Radix56 : IRadix
{
	public static int Bits => 56;
}

internal readonly struct Radix55 : IRadix
{
	public static int Bits => 55;
}

internal readonly struct Radix54 : IRadix
{
	public static int Bits => 54;
}

internal readonly struct Radix29 : IRadix
{
	public static int Bits => 29;
}

internal readonly struct Radix28 : IRadix
{
	public static int Bits => 28;
}

internal readonly struct Radix27 : IRadix
{
	public static int Bits => 27;
}

internal readonly struct Radix26 : IRadix
{
	public static int Bits => 26;
}
