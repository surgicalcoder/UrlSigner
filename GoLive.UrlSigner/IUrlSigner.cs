using System;

namespace GoLive.UrlSigner;

public interface IUrlSigner {

    string Sign(ReadOnlySpan<byte> key, ReadOnlySpan<char> url);

    Uri Sign(ReadOnlySpan<byte> key, Uri url);

    bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<char> url);

    bool Verify(ReadOnlySpan<byte> key, Uri url);

}