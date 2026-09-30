"""Cloudflare Access identity: verify the JWT Access puts on every request it admits.

PORTED VERBATIM from MagTer/price-tracker `src/api/cf_access.py` @ 0db887e (below this
header), for home-server APPLOGS-MIGRATION-DESIGN A3. Two copies on purpose: the two
apps release separately and share no package. A fix to one belongs in the other in the
same sitting; each file names the other.

Behind Cloudflare Access (the Kubernetes cluster on home-server, STATEFUL-APPS-DESIGN
D6) there is no oauth2-proxy and no X-Auth-Request-Email. Access forwards the user's
email as a plain `Cf-Access-Authenticated-User-Email` header too, and measured on the
lab (U2, 2026-09-30) a client-supplied copy of that header does not reach the origin.
It is still not read here: a plain header is only as good as every hop that could add
one, while the signed `Cf-Access-Jwt-Assertion` proves itself. Measured in the same
run, a forged assertion is REPLACED by Cloudflare's own, and a service-token request
carries a valid assertion with NO email claim, so "verified" does not imply "a person".

The verification is the one Cloudflare documents: RS256 only, signed by a key from the
team's certs endpoint, `aud` containing this application's AUD tag, `iss` the team
domain, and not expired.
"""

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
from joserfc import jws, jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

logger = logging.getLogger(__name__)

# Access signs with RS256. Accepting anything else is how a token signed with the
# PUBLIC key as an HMAC secret, or with alg "none", gets through.
ALGORITHMS = ("RS256",)

# Clock skew tolerated on exp/nbf/iat. Access tokens live for the session length, so a
# minute costs nothing and spares a refusal from a node clock a few seconds out.
LEEWAY_SECONDS = 60

# The certs endpoint is fetched again after this long even when the kid is known, so a
# key Cloudflare withdrew stops verifying within the hour. A NEW key needs no timer: an
# unknown kid refetches at once (below). Cloudflare's rotation cadence is deliberately
# not relied on anywhere here.
KEYS_TTL_SECONDS = 3600

# An unknown kid triggers a refetch (that is how a rotation arrives), but at most this
# often: otherwise a stream of tokens with invented kids turns into one outbound
# request each.
MIN_REFETCH_SECONDS = 30

CERTS_TIMEOUT_SECONDS = 5.0


class AccessTokenError(Exception):
    """The assertion did not verify. The message is a reason for the log, never a secret."""


def _fetch_certs(team_domain: str) -> dict[str, Any]:
    response = httpx.get(
        f"https://{team_domain}/cdn-cgi/access/certs", timeout=CERTS_TIMEOUT_SECONDS
    )
    response.raise_for_status()
    return response.json()


class AccessKeyCache:
    """The team's signing keys, fetched lazily and shared by every request.

    `get_principal` is a sync dependency, which FastAPI runs in its threadpool, so the
    cache is guarded by a lock. The fetch happens under that lock on purpose: during a
    rotation every waiting request wants the same answer, and one fetch serves them.
    """

    def __init__(
        self,
        fetch: Callable[[str], dict[str, Any]] = _fetch_certs,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._team: str | None = None
        self._keys: KeySet | None = None
        self._kids: frozenset[str] = frozenset()
        self._fetched_at = float("-inf")  # last SUCCESSFUL fetch: the TTL runs from here
        self._attempted_at = float("-inf")  # last attempt of any outcome: the spacing

    def key_set(self, team_domain: str, kid: str | None) -> KeySet:
        with self._lock:
            now = self._clock()
            if self._team != team_domain:
                # A different team (only ever a reconfiguration) shares nothing.
                self._team, self._keys, self._kids = team_domain, None, frozenset()
                self._fetched_at = self._attempted_at = float("-inf")

            fresh = now - self._fetched_at < KEYS_TTL_SECONDS
            if fresh and kid in self._kids:
                return self._keys  # type: ignore[return-value]

            if now - self._attempted_at >= MIN_REFETCH_SECONDS:
                self._attempted_at = now
                try:
                    keys = KeySet.import_key_set(self._fetch(team_domain))
                except Exception as exc:  # noqa: BLE001 — any failure means "cannot refresh"
                    # Keep the keys we have rather than forgetting them: an unreachable
                    # certs endpoint must not refuse tokens that verified a minute ago.
                    # With nothing cached, the caller cannot verify, and refuses.
                    logger.warning("Access certs fetch failed: %s", type(exc).__name__)
                else:
                    self._keys = keys
                    self._kids = frozenset(k.kid for k in keys.keys if k.kid)
                    self._fetched_at = now

            if self._keys is None:
                raise AccessTokenError("no signing keys: the certs endpoint has not answered")
            # An unknown kid falls through with the current keys, and the signature check
            # then refuses it: that is the right answer for a kid Cloudflare never issued.
            return self._keys


def verify_access_jwt(
    token: str,
    *,
    team_domain: str,
    audience: str,
    keys: AccessKeyCache,
    now: int | None = None,
) -> dict[str, Any]:
    """Return the verified claims of an Access assertion, or raise AccessTokenError."""
    try:
        # Read, NOT trusted: only to refuse a foreign alg early and pick the key.
        header = jws.extract_compact(token.encode()).protected
    except (JoseError, ValueError, UnicodeError) as exc:
        raise AccessTokenError(f"malformed token: {type(exc).__name__}") from exc
    if header.get("alg") not in ALGORITHMS:
        raise AccessTokenError(f"algorithm not accepted: {header.get('alg')!r}")

    key_set = keys.key_set(team_domain, header.get("kid"))
    try:
        decoded = jwt.decode(token, key_set, algorithms=list(ALGORITHMS))
    except JoseError as exc:
        raise AccessTokenError(f"signature: {type(exc).__name__}") from exc

    registry = jwt.JWTClaimsRegistry(
        now=now,
        leeway=LEEWAY_SECONDS,
        iss={"essential": True, "value": f"https://{team_domain}"},
        aud={"essential": True, "value": audience},
        exp={"essential": True},
    )
    try:
        registry.validate(decoded.claims)
    except JoseError as exc:
        reason = f"claims: {type(exc).__name__} {getattr(exc, 'claim', '')}".strip()
        raise AccessTokenError(reason) from exc
    return decoded.claims
