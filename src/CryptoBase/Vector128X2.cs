namespace CryptoBase;

[StructLayout(LayoutKind.Sequential)]
internal ref struct Vector128X2<T>
{
	public Vector128<T> V0;
	public Vector128<T> V1;
}
