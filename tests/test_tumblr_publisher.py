from src.tumblr_publisher import TumblrPublisher

class Resp:
    def __init__(self, data, status=200, headers=None): self._data, self.status_code, self.headers = data, status, headers or {}
    def json(self): return self._data

class FakeSession:
    def __init__(self): self.calls=[]
    def request(self, method, url, **kwargs):
        self.calls.append((method,url,kwargs))
        if url.endswith("/post"): return Resp({"response": {"id": 12345}}, status=201)
        raise AssertionError(url)

def test_publish_sequence_and_ids():
    session = FakeSession()
    pub = TumblrPublisher("testblog", "consumer-key", "consumer-secret", "oauth-token", "oauth-token-secret", session=session)
    result = pub.publish_video("https://raw.githubusercontent.com/a/b/main/videos/a.mp4", "caption #Travel")
    assert result["post_id"] == "12345"
    assert len(session.calls) == 1
    assert session.calls[0][0] == "POST"
    assert all("consumer-secret" not in call[1] and "consumer-secret" not in str(call[2].get("params", {})) for call in session.calls)
    assert all("oauth-token-secret" not in call[1] and "oauth-token-secret" not in str(call[2].get("params", {})) for call in session.calls)


def test_auth_failure_is_permanent_and_safe():
    class BadSession:
        def request(self, method, url, **kwargs):
            return Resp({}, status=401)
    from src.tumblr_publisher import TumblrError
    pub = TumblrPublisher("testblog", "consumer-key", "secret-consumer", "oauth-token", "secret-oauth", session=BadSession())
    try:
        pub.publish_video("https://raw.githubusercontent.com/a/b/main/videos/a.mp4", "caption")
        assert False, "expected auth error"
    except TumblrError as exc:
        assert exc.category == "authentication_or_permission"
        assert "secret-consumer" not in str(exc)
        assert "secret-oauth" not in str(exc)


def test_ambiguous_publish_timeout_is_flagged():
    from src.tumblr_publisher import TumblrError
    class TimeoutSession:
        def request(self, method, url, **kwargs):
            if url.endswith("/post"):
                raise TimeoutError("must not be surfaced")
            raise AssertionError(url)
    pub = TumblrPublisher("testblog", "consumer-key", "consumer-secret", "oauth-token", "oauth-token-secret", session=TimeoutSession())
    try:
        pub.publish_video("https://raw.githubusercontent.com/a/b/main/videos/a.mp4", "caption")
        assert False, "expected ambiguous error"
    except TumblrError as exc:
        assert exc.ambiguous is True
        assert "consumer-secret" not in str(exc)
        assert "oauth-token-secret" not in str(exc)


def test_retry_after_is_preserved_and_rate_limit_is_not_ambiguous():
    from src.tumblr_publisher import TumblrError
    class LimitedSession:
        def request(self, method, url, **kwargs):
            return Resp({}, status=429, headers={"Retry-After": "42"})
    pub = TumblrPublisher("testblog", "consumer-key", "consumer-secret", "oauth-token", "oauth-token-secret", session=LimitedSession())
    try:
        pub.publish_video("https://raw.githubusercontent.com/a/b/main/videos/a.mp4", "caption")
        assert False, "expected rate limit"
    except TumblrError as exc:
        assert exc.category == "rate_limited"
        assert exc.retry_after_seconds == 42
        assert exc.ambiguous is False


def test_hashtags_extracted_to_tags():
    session = FakeSession()
    pub = TumblrPublisher("testblog", "consumer-key", "consumer-secret", "oauth-token", "oauth-token-secret", session=session)
    result = pub.publish_video("https://example.com/video.mp4", "Beautiful scenery #Travel #Nature #Alps")
    assert result["post_id"] == "12345"
    # Verify the params sent include tags
    call_kwargs = session.calls[0][2]
    params = call_kwargs.get("params", {})
    assert "Travel" in params.get("tags", "")
    assert "Nature" in params.get("tags", "")
    assert "Alps" in params.get("tags", "")
