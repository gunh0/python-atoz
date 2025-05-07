"""Idempotency keys — retries are safe only if the server can recognise them

https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/

Once retries are in place (see retry_backoff.py) a new bug appears: the
request reached the server, the charge was made, but the response was lost on
the way back. The client times out, retries, and the customer pays twice. It is
easy to add retries around POST calls without noticing that POST is not
idempotent.

The pattern: the client generates one key per *logical* operation and sends
it with every attempt. The server stores key -> (fingerprint of the request,
response). A repeat with the same key and body replays the stored response; the
same key with a different body is a client bug and is rejected; a key whose
first attempt is still running gets "try again later", not a second charge.
"""

import hashlib
import json


def fingerprint(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class PaymentServer:
    def __init__(self) -> None:
        self.ledger: list[tuple[str, int]] = []
        self.keys: dict[str, tuple[str, dict | None]] = {}

    def _charge(self, body: dict) -> dict:
        self.ledger.append((body["customer"], body["amount"]))
        return {"status": 201, "charge_id": f"ch_{len(self.ledger):04d}"}

    def noncompliant(self, body: dict) -> dict:
        return self._charge(body)

    def compliant(self, key: str, body: dict) -> dict:
        fp = fingerprint(body)
        if key in self.keys:
            stored_fp, response = self.keys[key]
            if stored_fp != fp:
                return {"status": 422, "error": "idempotency key reused with a different body"}
            if response is None:
                return {"status": 409, "error": "original request still in progress"}
            return {**response, "replayed": True}
        self.keys[key] = (fp, None)  # claim the key before doing the work
        response = self._charge(body)
        self.keys[key] = (fp, response)
        return response


def client_with_lost_response(send, attempts: int = 3) -> dict:
    """The first response is dropped by the network; the client retries."""
    response = {}
    for attempt in range(attempts):
        response = send()
        if attempt == 0:
            continue  # timed out waiting: the client never saw this response
        return response
    return response


def main() -> None:
    body = {"customer": "cus_42", "amount": 1999}

    server = PaymentServer()
    final = client_with_lost_response(lambda: server.noncompliant(body))
    print(f"noncompliant: client saw {final}")
    print(f"noncompliant: ledger has {len(server.ledger)} charges {server.ledger}")
    print()

    server = PaymentServer()
    key = "8c1f0b9e-order-1187"  # in real clients: str(uuid.uuid4()) once per operation
    final = client_with_lost_response(lambda: server.compliant(key, body))
    print(f"compliant:    client saw {final}")
    print(f"compliant:    ledger has {len(server.ledger)} charge  {server.ledger}")
    print(f"compliant:    same key, new amount -> {server.compliant(key, {**body, 'amount': 5})}")

    other = {"customer": "cus_7", "amount": 500}
    server.keys["order-1188"] = (fingerprint(other), None)  # first attempt still running
    print(f"compliant:    key still in flight  -> {server.compliant('order-1188', other)}")
    print(f"compliant:    ledger still has {len(server.ledger)} charge")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: client saw {'status': 201, 'charge_id': 'ch_0002'}
# noncompliant: ledger has 2 charges [('cus_42', 1999), ('cus_42', 1999)]
#
# compliant:    client saw {'status': 201, 'charge_id': 'ch_0001', 'replayed': True}
# compliant:    ledger has 1 charge  [('cus_42', 1999)]
# compliant:    same key, new amount -> {'status': 422, 'error': 'idempotency key reused with a different body'}
# compliant:    key still in flight  -> {'status': 409, 'error': 'original request still in progress'}
# compliant:    ledger still has 1 charge
