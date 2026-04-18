using System;
using System.Security.Cryptography;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class HmacUrlSignerTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    private const string TestString = "https://www.example.com/";

    [Fact]
    public static void RoundtripString()
    {
        var signer = HmacUrlSigner<HMACSHA512>.Create(Key);
        var signedString = signer.Sign(TestString);
        Assert.True(signer.Verify(signedString));
    }

    [Fact]
    public static void RoundtripStringWithFragment()
    {
        const string origUrl = "https://www.example.com#myFragment";

        var signer = HmacUrlSigner<HMACSHA512>.Create(Key);
        var signedString = signer.Sign(origUrl);
        Assert.True(signer.Verify(signedString));
        Assert.EndsWith("#myFragment", signedString); // we want preserve fragment component

        var signedStringWithoutFragment = signedString.Replace("#myFragment", "");
        Assert.True(signer.Verify(signedStringWithoutFragment));
    }

    [Fact]
    public static void SignRejectsReservedSigParameter()
    {
        var signer = HmacUrlSigner<HMACSHA512>.Create(Key);

        var ex = Assert.Throws<ArgumentException>(() => signer.Sign("https://www.example.com/?sig=existing"));

        Assert.Contains("reserved 'sig'", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public static void VerifyReturnsFalseForMalformedSignature()
    {
        var signer = HmacUrlSigner<HMACSHA512>.Create(Key);

        Assert.False(signer.Verify("https://www.example.com/?sig=%%%"));
    }

    [Fact]
    public static void RoundtripSupportsSemicolonSeparatedQueryParameters()
    {
        const string url = "https://www.example.com/?token=abc;mode=download";
        var signer = HmacUrlSigner<HMACSHA512>.Create(Key);
        var signedUrl = signer.Sign(url);

        Assert.True(signer.Verify(signedUrl));
    }
}