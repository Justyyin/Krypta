using System.Net;
using System.Net.Http;
using Krypta.Core;

namespace Krypta.Tests;

public class EntrySearchTests
{
    private static readonly Entry GitHub = new() { Title = "GitHub", Username = "alice@example.com", Url = "https://www.github.com/login", Password = "Zq9secret", Notes = "work account" };
    private static readonly Entry Shop = new() { Title = "Shop", Username = "bob", Url = "shop.example.org", Password = "p" };
    private static readonly Entry Key = new() { Title = "Example", Passkey = new PasskeyData { RpId = "example.com", UserName = "carol@example.com" } };

    [Fact]
    public void Domain_is_taken_from_the_url_or_the_passkey()
    {
        Assert.Equal("github.com", EntrySearch.Domain(GitHub));
        Assert.Equal("shop.example.org", EntrySearch.Domain(Shop));
        Assert.Equal("example.com", EntrySearch.Domain(Key));
        Assert.Equal("", EntrySearch.Domain(new Entry { Title = "Wi-Fi", Url = "   " }));
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("git", true)]
    [InlineData("GIT alice", true)]
    [InlineData("github.com work", true)]
    [InlineData("git bob", false)]
    [InlineData("zq9", false)] // the password itself is never searched
    public void Search_needs_every_word_to_match(string query, bool expected) =>
        Assert.Equal(expected, EntrySearch.Matches(GitHub, query));

    [Theory]
    [InlineData("https://github.com", true)]
    [InlineData("https://www.github.com/login", true)]
    [InlineData("https://gist.github.com", true)]
    [InlineData("https://github.com.evil.net", false)]
    [InlineData("https://evilgithub.com", false)]
    [InlineData("https://hub.com", false)]
    [InlineData("not a url", false)]
    public void Logins_are_only_offered_on_their_own_website(string origin, bool expected)
    {
        Assert.Equal(expected, EntrySearch.MatchesOrigin(GitHub, origin));
        Assert.False(EntrySearch.MatchesOrigin(new Entry { Title = "no website" }, origin));
    }

    [Fact]
    public void Websites_are_counted_and_emails_collected()
    {
        var second = new Entry { Title = "GitHub 2", Username = "dave@example.com", Url = "https://github.com" };
        var sites = EntrySearch.Websites([GitHub, Shop, Key, second]);
        Assert.Equal(("github.com", 2), sites[0]);
        Assert.Equal(3, sites.Count);
        Assert.Equal(["alice@example.com", "carol@example.com", "dave@example.com"], EntrySearch.Emails([GitHub, Shop, Key, second]));
        Assert.False(EntrySearch.LooksLikeEmail("bob"));
        Assert.False(EntrySearch.LooksLikeEmail("a@b"));
        Assert.False(EntrySearch.LooksLikeEmail("a b@c.de"));
    }
}

public class SecurityAuditTests
{
    [Fact]
    public void Finds_reused_and_weak_passwords()
    {
        var a = new Entry { Title = "A", Password = "Tr0ub4dor&3-horse-staple!" };
        var b = new Entry { Title = "B", Password = "Tr0ub4dor&3-horse-staple!" };
        var weak = new Entry { Title = "C", Password = "hallo123" };
        var strong = new Entry { Title = "D", Password = PasswordGenerator.Generate(new PasswordOptions { Length = 24 }) };
        var none = new Entry { Title = "E" };

        var findings = SecurityAudit.Local([a, b, weak, strong, none]);
        Assert.Equal(2, findings.Count(f => f.Issue == PasswordIssue.Reused && f.Count == 2));
        Assert.Same(weak, Assert.Single(findings, f => f.Issue == PasswordIssue.Weak).Entry);
        Assert.DoesNotContain(findings, f => f.Entry == strong || f.Entry == none);
    }
}

public class HibpClientTests
{
    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancel)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage Text(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body) };

    [Fact]
    public async Task Password_check_sends_only_a_hash_prefix()
    {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        var handler = new FakeHandler(_ => Text("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFF:3"));
        var client = new HibpClient(handler);

        Assert.Equal(9545824, await client.PasswordLeakCountAsync("password"));
        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://api.pwnedpasswords.com/range/5BAA6", request.RequestUri!.AbsoluteUri);
        Assert.DoesNotContain("1E4C9B93", request.RequestUri.AbsoluteUri); // the rest of the hash stays here
        Assert.Equal("true", Assert.Single(request.Headers.GetValues("Add-Padding")));

        Assert.Equal(0, await client.PasswordLeakCountAsync("a password nobody has leaked"));
    }

    [Fact]
    public async Task Email_check_lists_breaches_and_treats_404_as_clean()
    {
        var handler = new FakeHandler(request => request.RequestUri!.AbsoluteUri.Contains("clean")
            ? Text("", HttpStatusCode.NotFound)
            : Text("""[{"Name":"Adobe"},{"Name":"LinkedIn"}]"""));
        var client = new HibpClient(handler);

        Assert.Equal(["Adobe", "LinkedIn"], await client.BreachesForEmailAsync(" alice+x@example.com ", "key123"));
        var request = handler.Requests[0];
        Assert.Equal("https://haveibeenpwned.com/api/v3/breachedaccount/alice%2Bx%40example.com?truncateResponse=true", request.RequestUri!.AbsoluteUri);
        Assert.Equal("key123", Assert.Single(request.Headers.GetValues("hibp-api-key")));
        Assert.NotEmpty(request.Headers.UserAgent);

        Assert.Empty(await client.BreachesForEmailAsync("clean@example.com", "key123"));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "api-key")]
    [InlineData(HttpStatusCode.TooManyRequests, "rate-limit")]
    [InlineData(HttpStatusCode.InternalServerError, "network")]
    public async Task Errors_are_reported_by_kind(HttpStatusCode status, string code)
    {
        var client = new HibpClient(new FakeHandler(_ => Text("", status)));
        var error = await Assert.ThrowsAsync<HibpException>(() => client.BreachesForEmailAsync("a@example.com", "k"));
        Assert.Equal(code, error.Code);
    }
}
