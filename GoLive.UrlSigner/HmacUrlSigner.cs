using System;
using System.Security.Cryptography;

namespace GoLive.UrlSigner;
public class HmacUrlSigner<TAlg> : UrlSigner where TAlg : KeyedHashAlgorithm, new()
{
    public HmacUrlSigner(ReadOnlyMemory<byte> key) : base(key)
    {
    }

    public static HmacUrlSigner<TAlg> Create(ReadOnlyMemory<byte> key) => new(key);

    protected override byte[] GetSignature(ReadOnlySpan<byte> data)
    {
        using var alg = new TAlg();
        alg.Key = Key.ToArray();
        return alg.ComputeHash(data.ToArray());
    }

    protected override bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig) 
    {
        var correctSig = GetSignature(data);
        return CryptographicOperations.FixedTimeEquals(correctSig, sig);
    }

}