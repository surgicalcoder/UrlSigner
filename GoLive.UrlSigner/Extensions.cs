using System.Text;

namespace GoLive.UrlSigner;

public static class Extensions
{
    private static readonly char[] QuerySeparatorChars = { '&', ';' };

    internal static string CanonicalizeQuery(this ReadOnlySpan<char> url)
    {
        EnsureHasValue(url, nameof(url));

        var baseUrl = url.RemoveFragment(out _);
        var queryIndex = baseUrl.IndexOf('?');

        if (queryIndex < 0 || queryIndex == baseUrl.Length - 1)
        {
            return baseUrl;
        }

        var path = baseUrl[..queryIndex];
        var segments = ParseSegments(baseUrl[(queryIndex + 1)..]);

        Array.Sort(segments, static (left, right) =>
        {
            var nameComparison = StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name);
            if (nameComparison != 0)
            {
                return nameComparison;
            }

            var valueComparison = StringComparer.Ordinal.Compare(left.Value, right.Value);
            if (valueComparison != 0)
            {
                return valueComparison;
            }

            var textComparison = StringComparer.Ordinal.Compare(left.Text, right.Text);
            if (textComparison != 0)
            {
                return textComparison;
            }

            return left.OriginalIndex.CompareTo(right.OriginalIndex);
        });

        var builder = new StringBuilder(path);
        builder.Append('?');

        for (var i = 0; i < segments.Length; i++)
        {
            if (i > 0)
            {
                builder.Append('&');
            }

            builder.Append(segments[i].Text);
        }

        return builder.ToString();
    }

    internal static string RemoveParameter(this ReadOnlySpan<char> url, ReadOnlySpan<char> paramName, out string paramValue)
    {
        EnsureHasValue(url, nameof(url));
        EnsureHasValue(paramName, nameof(paramName));

        var baseUrl = url.RemoveFragment(out var fragment);
        var queryIndex = baseUrl.IndexOf('?');

        if (queryIndex < 0 || queryIndex == baseUrl.Length - 1)
        {
            throw new FormatException("Invalid URL format");
        }

        var path = baseUrl[..queryIndex];
        var query = baseUrl[(queryIndex + 1)..];
        var segments = ParseSegments(query);
        var matchIndex = -1;
        paramValue = string.Empty;

        for (var i = 0; i < segments.Length; i++)
        {
            if (!segments[i].HasName(paramName))
            {
                continue;
            }

            if (matchIndex >= 0)
            {
                throw new FormatException($"Parameter '{paramName.ToString()}' appears more than once.");
            }

            matchIndex = i;
            paramValue = segments[i].Value;
        }

        if (matchIndex < 0)
        {
            throw new FormatException($"Parameter '{paramName.ToString()}' was not found.");
        }

        var builder = new StringBuilder(path);
        var hasQuery = false;

        for (var i = 0; i < segments.Length; i++)
        {
            if (i == matchIndex)
            {
                continue;
            }

            builder.Append(hasQuery ? segments[i].SeparatorBefore : '?');
            builder.Append(segments[i].Text);
            hasQuery = true;
        }

        builder.Append(fragment);
        return builder.ToString();
    }

    internal static string AppendParameter(this ReadOnlySpan<char> url, ReadOnlySpan<char> paramName, ReadOnlySpan<char> paramValue)
    {
        EnsureHasValue(url, nameof(url));
        EnsureHasValue(paramName, nameof(paramName));

        var baseUrl = RemoveFragment(url, out var fragment);
        var separator = baseUrl.Contains('?') ? '&' : '?';
        return string.Concat(baseUrl, separator.ToString(), paramName.ToString(), "=", paramValue.ToString(), fragment);
    }

    internal static bool ContainsParameter(this ReadOnlySpan<char> url, ReadOnlySpan<char> paramName)
    {
        EnsureHasValue(url, nameof(url));
        EnsureHasValue(paramName, nameof(paramName));

        var baseUrl = url.RemoveFragment();
        var queryIndex = baseUrl.IndexOf('?');

        if (queryIndex < 0 || queryIndex == baseUrl.Length - 1)
        {
            return false;
        }

        foreach (var segment in ParseSegments(baseUrl[(queryIndex + 1)..]))
        {
            if (segment.HasName(paramName))
            {
                return true;
            }
        }

        return false;
    }

    internal static string RemoveFragment(this ReadOnlySpan<char> url) => RemoveFragment(url, out _);

    internal static string RemoveFragment(this ReadOnlySpan<char> url, out string fragment)
    {
        EnsureHasValue(url, nameof(url));

        var urlString = url.ToString();
        var fragmentIndex = urlString.IndexOf('#');

        if (fragmentIndex < 0)
        {
            fragment = string.Empty;
            return urlString;
        }

        fragment = urlString[fragmentIndex..];
        return urlString[..fragmentIndex];
    }

    private static QuerySegment[] ParseSegments(string query)
    {
        var segments = new QuerySegment[query.Count(c => c is '&' or ';') + 1];
        var segmentStart = 0;
        var separatorBefore = '&';
        var segmentIndex = 0;

        for (var i = 0; i <= query.Length; i++)
        {
            if (i < query.Length && !QuerySeparatorChars.AsSpan().Contains(query[i]))
            {
                continue;
            }

            var text = query[segmentStart..i];
            segments[segmentIndex] = new QuerySegment(segmentIndex, separatorBefore, text);
            segmentIndex++;

            if (i < query.Length)
            {
                separatorBefore = query[i];
                segmentStart = i + 1;
            }
        }

        return segments;
    }

    private static void EnsureHasValue(ReadOnlySpan<char> value, string paramName)
    {
        if (value.IsEmpty || value.IsWhiteSpace())
        {
            throw new ArgumentException("Value cannot be empty or whitespace only string.", paramName);
        }
    }

    private readonly record struct QuerySegment(int OriginalIndex, char SeparatorBefore, string Text)
    {
        public string Name
        {
            get
            {
                var equalsIndex = Text.IndexOf('=');
                return equalsIndex < 0 ? Text : Text[..equalsIndex];
            }
        }

        public string Value
        {
            get
            {
                var equalsIndex = Text.IndexOf('=');
                return equalsIndex < 0 ? string.Empty : Text[(equalsIndex + 1)..];
            }
        }

        public bool HasName(ReadOnlySpan<char> name)
        {
            var equalsIndex = Text.IndexOf('=');
            var key = equalsIndex < 0 ? Text.AsSpan() : Text.AsSpan(0, equalsIndex);
            return key.Equals(name, StringComparison.OrdinalIgnoreCase);
        }
    }
}
