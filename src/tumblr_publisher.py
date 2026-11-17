from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, time, uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from io import BufferedReader
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit, parse_qsl
from urllib.request import Request, urlopen


class TumblrError(RuntimeError):
    def __init__(self, category: str, message: str, transient: bool = False, ambiguous: bool = False, retry_after_seconds: int | None = None):
        super().__init__(message)
        self.category, self.transient, self.ambiguous = category, transient, ambiguous
        self.retry_after_seconds = retry_after_seconds


class TumblrPublisher:
    def __init__(self, blog_name: str, consumer_key: str, consumer_secret: str,
                 oauth_token: str, oauth_token_secret: str,
                 base_url: str = "https://api.tumblr.com/v2", timeout: int = 60,
                 session=None):
        if not all((blog_name, consumer_key, consumer_secret, oauth_token, oauth_token_secret)):
            raise ValueError("Tumblr credentials are missing")
        self.blog = blog_name
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session  # Optional test adapter; production uses Python stdlib HTTP only.

    @staticmethod
    def _percent_encode(s: str) -> str:
        return quote(str(s), safe="")

    def _oauth_signature(self, method: str, url: str, params: dict) -> str:
        """Generate OAuth 1.0a HMAC-SHA1 signature."""
        sorted_params = "&".join(
            f"{self._percent_encode(k)}={self._percent_encode(v)}"
            for k, v in sorted(params.items())
        )
        # Strip query string from URL for base string
        parts = urlsplit(url)
        base_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        base_string = "&".join(map(self._percent_encode, [method.upper(), base_url, sorted_params]))
        signing_key = f"{self._percent_encode(self.consumer_secret)}&{self._percent_encode(self.oauth_token_secret)}"
        signature = hmac.new(signing_key.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha1)
        return base64.b64encode(signature.digest()).decode("ascii")

    def _oauth_header(self, method: str, url: str, extra_params: dict | None = None) -> str:
        """Build the OAuth Authorization header value."""
        oauth_params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": secrets.token_hex(16),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_token": self.oauth_token,
            "oauth_version": "1.0",
        }
        all_params = {**oauth_params}
        if extra_params:
            all_params.update(extra_params)
        signature = self._oauth_signature(method, url, all_params)
        oauth_params["oauth_signature"] = signature
        header_parts = ", ".join(
            f'{self._percent_encode(k)}="{self._percent_encode(v)}"'
            for k, v in sorted(oauth_params.items())
        )
        return f"OAuth {header_parts}"

    def _request(self, method: str, url: str, *, params: dict | None = None, body: bytes | None = None, content_type: str | None = None):
        response_headers = {}
        try:
            if self.session is not None:
                response = self.session.request(method, url, params=params, headers={"Authorization": "OAuth test"}, timeout=self.timeout)
                status_code = response.status_code
                response_headers = getattr(response, "headers", {}) or {}
                data = response.json() if 200 <= status_code < 300 else None
            else:
                if method.upper() == "GET" and params:
                    parts = urlsplit(url)
                    existing = parse_qsl(parts.query, keep_blank_values=True)
                    query = urlencode(existing + list(params.items()))
                    request_url = urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
                    auth_header = self._oauth_header(method, url, extra_params=params)
                else:
                    request_url = url
                    # For POST with form-encoded body, include params in signature
                    auth_header = self._oauth_header(method, url, extra_params=params if params and not body else None)

                headers = {"Authorization": auth_header, "Accept": "application/json"}
                if body is not None:
                    req = Request(request_url, data=body, headers=headers, method=method.upper())
                    if content_type:
                        req.add_header("Content-Type", content_type)
                elif params and method.upper() == "POST":
                    encoded_body = urlencode(params).encode("utf-8")
                    req = Request(request_url, data=encoded_body, headers=headers, method="POST")
                    req.add_header("Content-Type", "application/x-www-form-urlencoded")
                else:
                    req = Request(request_url, headers=headers, method=method.upper())

                try:
                    with urlopen(req, timeout=self.timeout) as response:
                        status_code = response.status
                        response_headers = response.headers
                        raw = response.read()
                except HTTPError as response:
                    status_code = response.code
                    response_headers = response.headers
                    raw = response.read() if response.fp else b""
                data = json.loads(raw.decode("utf-8")) if raw else None
        except TumblrError:
            raise
        except TimeoutError as exc:
            raise TumblrError("network_timeout", "Tumblr API request timed out", transient=True, ambiguous=(method.upper() == "POST")) from exc
        except (URLError, OSError) as exc:
            raise TumblrError("network_error", "Tumblr API network error", transient=True, ambiguous=(method.upper() == "POST")) from exc
        except (ValueError, json.JSONDecodeError) as exc:
            raise TumblrError("invalid_response", "Tumblr API returned invalid JSON") from exc

        if status_code == 429:
            retry_after = None
            raw_retry_after = response_headers.get("Retry-After") if response_headers else None
            if raw_retry_after:
                try:
                    retry_after = max(0, int(raw_retry_after))
                except (ValueError, TypeError):
                    try:
                        retry_date = parsedate_to_datetime(raw_retry_after)
                        if retry_date.tzinfo is None:
                            retry_date = retry_date.replace(tzinfo=timezone.utc)
                        retry_after = max(0, int((retry_date - datetime.now(timezone.utc)).total_seconds()))
                    except (TypeError, ValueError, OverflowError):
                        retry_after = None
            raise TumblrError("rate_limited", "Tumblr API rate limit reached", transient=True, retry_after_seconds=retry_after)
        if status_code in (401, 403):
            raise TumblrError("authentication_or_permission", f"Tumblr API returned HTTP {status_code}")
        if status_code >= 500:
            raise TumblrError("server_error", f"Tumblr API returned HTTP {status_code}", transient=True, ambiguous=(method.upper() == "POST"))
        if not (200 <= status_code < 300) and status_code != 201:
            raise TumblrError("request_rejected", f"Tumblr API rejected request with HTTP {status_code}")
        if not isinstance(data, dict):
            raise TumblrError("invalid_response", "Tumblr API returned an unexpected response structure")
        return data

    def publish_video(self, video_url: str, caption: str, video_data: bytes | None = None) -> dict:
        """Create a video post on Tumblr.

        If video_data is provided (bytes), uploads the file directly as multipart form data.
        Otherwise, creates a video post using an external URL (for embeds like YouTube).
        """
        tags = []
        # Extract hashtags from caption and convert to Tumblr tags
        caption_text = caption or ""
        words = caption_text.split()
        clean_parts = []
        for word in words:
            if word.startswith("#"):
                tag = word.lstrip("#").strip()
                if tag:
                    tags.append(tag)
            else:
                clean_parts.append(word)
        body_text = " ".join(clean_parts).strip()

        if video_data is not None:
            # Upload video directly as multipart form data
            boundary = f"----{uuid.uuid4().hex}"
            parts = []

            # Add form fields
            parts.append(f"--{boundary}".encode())
            parts.append('Content-Disposition: form-data; name="type"'.encode())
            parts.append(b"")
            parts.append(b"video")

            parts.append(f"--{boundary}".encode())
            parts.append('Content-Disposition: form-data; name="caption"'.encode())
            parts.append(b"")
            parts.append(body_text.encode("utf-8"))

            if tags:
                parts.append(f"--{boundary}".encode())
                parts.append('Content-Disposition: form-data; name="tags"'.encode())
                parts.append(b"")
                parts.append(",".join(tags).encode("utf-8"))

            # Add video file
            parts.append(f"--{boundary}".encode())
            parts.append('Content-Disposition: form-data; name="data"; filename="video.mp4"'.encode())
            parts.append(b"Content-Type: video/mp4")
            parts.append(b"")
            parts.append(video_data)
            parts.append(f"--{boundary}--".encode())

            body = b"\r\n".join(parts)
            content_type = f"multipart/form-data; boundary={boundary}"

            url = f"{self.base}/blog/{self.blog}/post"
            try:
                result = self._request("POST", url, body=body, content_type=content_type)
            except TumblrError as exc:
                if exc.transient and exc.category in {"network_timeout", "network_error", "server_error"}:
                    exc.ambiguous = True
                raise

            response_data = result.get("response", {})
            post_id = response_data.get("id") if isinstance(response_data, dict) else None
            if not post_id:
                post_id = result.get("id")
            if not post_id:
                raise TumblrError("publication_unconfirmed", "Publish response did not include a post ID", ambiguous=True)

            return {"post_id": str(post_id)}

        else:
            # Use external URL (for embeds like YouTube)
            params = {
                "type": "video",
                "caption": body_text,
                "embed": video_url,  # Use 'embed' for external URLs
            }
            if tags:
                params["tags"] = ",".join(tags)

            url = f"{self.base}/blog/{self.blog}/post"
            try:
                result = self._request("POST", url, params=params)
            except TumblrError as exc:
                if exc.transient and exc.category in {"network_timeout", "network_error", "server_error"}:
                    exc.ambiguous = True
                raise

            response_data = result.get("response", {})
            post_id = response_data.get("id") if isinstance(response_data, dict) else None
            if not post_id:
                post_id = result.get("id")
            if not post_id:
                raise TumblrError("publication_unconfirmed", "Publish response did not include a post ID", ambiguous=True)

            return {"post_id": str(post_id)}
