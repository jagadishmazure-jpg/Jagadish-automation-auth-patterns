"""Demo: OAuth client-credentials with caching and proactive refresh."""
import sys
sys.path.insert(0, ".")

from authpatterns.clock import FakeClock
from authpatterns.oauth import FakeTokenEndpoint, OAuthClient

clock = FakeClock()
endpoint = FakeTokenEndpoint(clock)
endpoint.register("scheduler", "scheduler-secret")
client = OAuthClient("scheduler", "scheduler-secret", endpoint, clock,
                     refresh_margin_seconds=120)

t1 = client.get_token()
print("token acquired, valid:", bool(endpoint.validate(t1)))

clock.advance(minutes=30)
t2 = client.get_token()
print("cache hit (same token):", t1 == t2)

clock.advance(minutes=29)  # 1 minute of life left < 120s margin
t3 = client.get_token()
print("proactive refresh (new token):", t3 != t1)
print("refreshed token valid:", bool(endpoint.validate(t3)))
