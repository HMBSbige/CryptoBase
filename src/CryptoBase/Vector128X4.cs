namespace CryptoBase;

[StructLayout(LayoutKind.Sequential)]
internal ref struct Vector128X4<T>
{
	public Vector128<T> V0;
	public Vector128<T> V1;
	public Vector128<T> V2;
	public Vector128<T> V3;
}
