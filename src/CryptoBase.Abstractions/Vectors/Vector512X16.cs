namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Sequential)]
public ref struct Vector512X16<T>
{
	public Vector512<T> V0;
	public Vector512<T> V1;
	public Vector512<T> V2;
	public Vector512<T> V3;
	public Vector512<T> V4;
	public Vector512<T> V5;
	public Vector512<T> V6;
	public Vector512<T> V7;
	public Vector512<T> V8;
	public Vector512<T> V9;
	public Vector512<T> V10;
	public Vector512<T> V11;
	public Vector512<T> V12;
	public Vector512<T> V13;
	public Vector512<T> V14;
	public Vector512<T> V15;
}
