using System;
using System.Security.Cryptography;

namespace GoLive.UrlSigner;
public class HmacUrlSigner<TAlg> : UrlSigner where TAlg : KeyedHashAlgorithm, new() {
    protected override byte[] GetSignature(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        using (var alg = new TAlg { Key = key.ToArray() })
        {
            return alg.ComputeHash(data.ToArray());
        }
    }

    protected override bool VerifySignature(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig) {
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        if (sig == null)
        {
            throw new ArgumentNullException(nameof(sig));
        }

        // Compute correct signature
        var correctSig = this.GetSignature(key, data);
        if (correctSig.Length != sig.Length) return false;

        // Constant time compare
        var result = 0;
        for (var i = 0; i < correctSig.Length; i++) {
            result |= sig[i] ^ correctSig[i];
        }
        return result == 0;
    }

}