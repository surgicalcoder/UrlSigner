using System;

namespace GoLive.UrlSigner;

public interface IUrlSigner {

    string Sign(ReadOnlySpan<char> url);

    Uri Sign(Uri url);

    bool Verify(ReadOnlySpan<char> url);

    bool Verify(Uri url);
    
    public ReadOnlyMemory<byte> Key { set; }
}