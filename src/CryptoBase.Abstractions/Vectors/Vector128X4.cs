namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Sequential)]
public ref struct Vector128X4<T>
{
	public Vector128<T> V0;
	public Vector128<T> V1;
	public Vector128<T> V2;
	public Vector128<T> V3;
}
