namespace CryptoBase;

[StructLayout(LayoutKind.Sequential)]
internal ref struct Vector128X8<T>
{
	public Vector128<T> V0;
	public Vector128<T> V1;
	public Vector128<T> V2;
	public Vector128<T> V3;
	public Vector128<T> V4;
	public Vector128<T> V5;
	public Vector128<T> V6;
	public Vector128<T> V7;
}
