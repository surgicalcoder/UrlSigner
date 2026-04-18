using System;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class TimedUrlSignerTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    private static readonly TimeSpan TestTtl = TimeSpan.FromSeconds(1);
    private const string TestString = "https://www.example.com/";

    [Fact]
    public static void ImmediateRoundtripString()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-04-18T12:00:00Z"));
        var signer = TimedUrlSigner.Create(Key, timeProvider);
        var signedString = signer.Sign(TestString, TestTtl);

        timeProvider.Advance(TestTtl / 2);

        Assert.True(signer.Verify(signedString));
    }

    [Fact]
    public static void ImmediateRoundtripStringWithFragment()
    {
        const string origUrl = "https://www.example.com#myFragment";
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-04-18T12:00:00Z"));

        var signer = TimedUrlSigner.Create(Key, timeProvider);
        var signedString = signer.Sign(origUrl, TestTtl);

        timeProvider.Advance(TestTtl / 2);

        Assert.True(signer.Verify(signedString));
        Assert.EndsWith("#myFragment", signedString); // we want preserve fragment component

        var signedStringWithoutFragment = signedString.Replace("#myFragment", "");
        Assert.True(signer.Verify(signedStringWithoutFragment));
    }

    [Fact]
    public static void ExpiredRoundtripString()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-04-18T12:00:00Z"));
        var signer = TimedUrlSigner.Create(Key, timeProvider);
        var signedString = signer.Sign(TestString, TestTtl);

        timeProvider.Advance(TestTtl * 2);

        Assert.False(signer.Verify(signedString));
    }

    [Fact]
    public static void StaticHelpersSupportDirectKeyUsage()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-04-18T12:00:00Z"));
        var signedString = TimedUrlSigner.Sign(TestString, TestTtl, Key, timeProvider);

        timeProvider.Advance(TestTtl / 2);

        Assert.True(TimedUrlSigner.Verify(signedString, Key, timeProvider));
    }

    [Fact]
    public static void SignRejectsReservedExpParameter()
    {
        var signer = TimedUrlSigner.Create(Key);

        var ex = Assert.Throws<ArgumentException>(() => signer.Sign("https://www.example.com/?exp=already-there", TestTtl));

        Assert.Contains("reserved 'exp'", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public static void SignRejectsNonPositiveTtl()
    {
        var signer = TimedUrlSigner.Create(Key);

        Assert.Throws<ArgumentOutOfRangeException>(() => signer.Sign(TestString, TimeSpan.Zero));
    }

    [Fact]
    public static void VerifyReturnsFalseForDuplicateExpWhenSignatureIsOtherwiseValid()
    {
        const string urlWithDuplicateExp = "https://www.example.com/?token=abc&exp=1776515100&exp=1776515200";
        var rawSigner = HmacUrlSigner<System.Security.Cryptography.HMACSHA512>.Create(Key);
        var timedSigner = TimedUrlSigner.Create(Key, new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1776515000)));
        var signedUrl = rawSigner.Sign(urlWithDuplicateExp);

        Assert.False(timedSigner.Verify(signedUrl));
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset currentUtcNow;

        public FakeTimeProvider(DateTimeOffset utcNow)
        {
            currentUtcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => currentUtcNow;

        public void Advance(TimeSpan by) => currentUtcNow = currentUtcNow.Add(by);
    }

}