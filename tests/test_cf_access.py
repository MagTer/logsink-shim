"""AUTH_SOURCE=cf-access: the admin's identity comes from a verified Access JWT only.

home-server APPLOGS-MIGRATION-DESIGN A3. Real RS256 keys and real signatures; only
the certs endpoint is replaced, by a fetch function serving this file's JWKS. Every
refusal goes through the real admin chain, because the chain is what is tested. The
verifier itself is price-tracker's (cf_access.py says so), so its own edge cases are
covered again here only where the shim could wire them wrongly.
"""

import time

import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet, OctKey, RSAKey

import logsink_shim.app as shim
from logsink_shim.cf_access import AccessKeyCache

TEAM = "example.cloudflareaccess.com"
AUD = "b" * 64
ADMIN = "magnus@example.com"

SIGNING_KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})
# Same kid, different key: what a forger who read the kid off a real token would use.
FORGER_KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})


def token(*, key: RSAKey | OctKey = SIGNING_KEY, alg: str = "RS256", **overrides) -> str:
    now = int(time.time())
    claims = {
        "aud": [AUD],
        "email": ADMIN,
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "iss": f"https://{TEAM}",
        "sub": "0000",
        "type": "app",
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode({"alg": alg, "kid": "k1"}, claims, key, algorithms=[alg])


@pytest.fixture
def served_keys(monkeypatch):
    state = {"fail": False}

    def fetch(team_domain):
        assert team_domain == TEAM
        if state["fail"]:
            raise ConnectionError("certs endpoint down")
        return KeySet([SIGNING_KEY]).as_dict(private=False)

    monkeypatch.setattr(shim, "_access_keys", AccessKeyCache(fetch=fetch))
    return state


@pytest.fixture
def client(monkeypatch, served_keys):
    monkeypatch.setenv("LOGSINK_KEYS", "sekret1:retro-fm")
    monkeypatch.setenv("LOGSINK_ADMIN_EMAILS", ADMIN)
    monkeypatch.setenv("LOGSINK_ADMIN_TOKEN", "admintoken")
    monkeypatch.setenv("AUTH_SOURCE", "cf-access")
    monkeypatch.setenv("CF_ACCESS_TEAM_DOMAIN", TEAM)
    monkeypatch.setenv("CF_ACCESS_AUD", AUD)
    shim.state = shim.State()
    return TestClient(shim.app)


def levels(client, assertion=None, **headers):
    if assertion is not None:
        headers["Cf-Access-Jwt-Assertion"] = assertion
    return client.get("/admin/levels", headers=headers)


class TestAccepted:
    def test_valid_assertion_for_the_admin(self, client):
        assert levels(client, token()).status_code == 200

    def test_the_admin_page_and_a_level_change_too(self, client):
        h = {"Cf-Access-Jwt-Assertion": token()}
        assert client.get("/admin", headers=h).status_code == 200
        r = client.put("/admin/level/retro-fm", headers=h, json={"level": "DEBUG"})
        assert r.status_code == 200 and r.json()["level"] == "DEBUG"

    def test_email_case_is_ignored(self, client):
        assert levels(client, token(email=ADMIN.upper())).status_code == 200

    def test_the_machine_bearer_still_works(self, client):
        assert levels(client, Authorization="Bearer admintoken").status_code == 200


class TestRefused:
    def test_wrong_aud(self, client):
        assert levels(client, token(aud=["c" * 64])).status_code == 401

    def test_expired(self, client):
        past = int(time.time()) - 7200
        assert levels(client, token(exp=past, iat=past - 60, nbf=past - 60)).status_code == 401

    def test_forged_header_without_a_token(self, client):
        # The Dokploy header means nothing in this mode.
        assert levels(client, **{"X-Auth-Request-Email": ADMIN}).status_code == 401

    def test_forged_header_beside_a_valid_token_for_someone_else(self, client):
        r = levels(client, token(email="other@example.com"), **{"X-Auth-Request-Email": ADMIN})
        assert r.status_code == 401

    def test_missing_token(self, client):
        assert levels(client).status_code == 401

    def test_service_token_assertion_names_nobody(self, client):
        # What the ingest token's requests carry (STATEFUL-APPS U2): valid, no email.
        assert levels(client, token(email=None, common_name="x.access")).status_code == 401

    def test_signed_by_another_key_with_the_same_kid(self, client):
        assert levels(client, token(key=FORGER_KEY)).status_code == 401

    def test_hs256_with_the_public_key_as_secret(self, client):
        secret = OctKey.import_key(SIGNING_KEY.as_pem(private=False))
        assert levels(client, token(key=secret, alg="HS256")).status_code == 401

    def test_wrong_issuer(self, client):
        assert levels(client, token(iss="https://evil.cloudflareaccess.com")).status_code == 401

    def test_garbage(self, client):
        assert levels(client, "not.a.jwt").status_code == 401

    def test_missing_aud_setting_refuses_the_email_path(self, client, monkeypatch):
        monkeypatch.delenv("CF_ACCESS_AUD")
        assert levels(client, token()).status_code == 401

    def test_unknown_auth_source_refuses_everything(self, client, monkeypatch):
        monkeypatch.setenv("AUTH_SOURCE", "cf-acess")
        assert levels(client, token()).status_code == 503
        assert levels(client, Authorization="Bearer admintoken").status_code == 503

    def test_certs_endpoint_down_with_nothing_cached(self, client, served_keys):
        served_keys["fail"] = True
        assert levels(client, token()).status_code == 401


class TestOneSourceAtATime:
    def test_default_source_ignores_an_access_token(self, client, monkeypatch):
        monkeypatch.delenv("AUTH_SOURCE")
        assert levels(client, token()).status_code == 401

    def test_default_source_still_reads_the_dokploy_header(self, client, monkeypatch):
        monkeypatch.delenv("AUTH_SOURCE")
        assert levels(client, **{"X-Auth-Request-Email": ADMIN}).status_code == 200


class TestIngestUnchanged:
    def test_ingest_config_still_needs_only_the_app_key(self, client):
        r = client.get("/ingest/config", headers={"Authorization": "Bearer sekret1"})
        assert r.status_code == 200 and r.json()["app"] == "retro-fm"

    def test_an_admin_assertion_is_not_an_ingest_key(self, client):
        r = client.get("/ingest/config", headers={"Cf-Access-Jwt-Assertion": token()})
        assert r.status_code == 401
