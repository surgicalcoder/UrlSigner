using System;
using System.Security.Cryptography;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class HmacUrlSignerTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    private static readonly Uri TestUri = new Uri("https://www.example.com/");
    private const string TestString = "https://www.example.com/";

    [Fact]
    public static void RoundtripUri()
    {
        var signer = new HmacUrlSigner<HMACSHA512>();
        var signedUri = signer.Sign(Key, TestUri);
        Assert.True(signer.Verify(Key, signedUri));
    }

    [Fact]
    public static void RoundtripString()
    {
        var signer = new HmacUrlSigner<HMACSHA512>();
        var signedString = signer.Sign(Key, TestString);
        Assert.True(signer.Verify(Key, signedString));
    }

    [Fact]
    public static void RoundtripStringWithFragment()
    {
        const string origUrl = "https://www.example.com#myFragment";

        var signer = new HmacUrlSigner<HMACSHA512>();
        var signedString = signer.Sign(Key, origUrl);
        Assert.True(signer.Verify(Key, signedString));
        Assert.EndsWith("#myFragment", signedString); // we want preserve fragment component

        var signedStringWithoutFragment = signedString.Replace("#myFragment", "");
        Assert.True(signer.Verify(Key, signedStringWithoutFragment));
    }
}