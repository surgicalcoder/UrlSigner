using System;

namespace GoLive.UrlSigner;

public interface IUrlSigner {
    string Sign(ReadOnlySpan<char> url);

    bool Verify(ReadOnlySpan<char> url);
}