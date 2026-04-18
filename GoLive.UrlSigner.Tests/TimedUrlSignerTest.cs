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

    [Fact]
    public static void VerifySucceedsWhenTimedSignedUrlQueryParametersAreReordered()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-04-18T12:00:00Z"));
        var signer = TimedUrlSigner.Create(Key, timeProvider);
        var signedUrl = signer.Sign("https://www.example.com/?b=2&a=1", TestTtl);
        var reorderedSignedUrl = ReorderQuery(signedUrl, "a", "b", "exp", "sig");

        timeProvider.Advance(TestTtl / 2);

        Assert.True(signer.Verify(reorderedSignedUrl));
    }

    private static string ReorderQuery(string url, params string[] orderedParameterNames)
    {
        var queryIndex = url.IndexOf('?');
        if (queryIndex < 0)
        {
            return url;
        }

        var prefix = url[..queryIndex];
        var segments = url[(queryIndex + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries);
        var reorderedSegments = new string[segments.Length];
        var index = 0;

        foreach (var parameterName in orderedParameterNames)
        {
            foreach (var segment in segments)
            {
                if (segment.StartsWith(parameterName + "=", StringComparison.Ordinal))
                {
                    reorderedSegments[index++] = segment;
                }
            }
        }

        foreach (var segment in segments)
        {
            var alreadyAdded = false;
            for (var i = 0; i < index; i++)
            {
                if (string.Equals(reorderedSegments[i], segment, StringComparison.Ordinal))
                {
                    alreadyAdded = true;
                    break;
                }
            }

            if (!alreadyAdded)
            {
                reorderedSegments[index++] = segment;
            }
        }

        return $"{prefix}?{string.Join("&", reorderedSegments, 0, index)}";
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