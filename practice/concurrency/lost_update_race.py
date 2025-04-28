"""Lost update: a read-modify-write race, forced to happen every time

https://cwe.mitre.org/data/definitions/362.html

A common pattern shares an object between worker threads and does
`balance = account.balance; ...; account.balance = balance + amount`. The quick
test that comes with it usually passes, because the GIL switches threads
rarely enough that the two steps almost never interleave. "Almost never" is a
production incident waiting for load.

Do not hunt races with sleeps and luck. Put a hook between the read and the
write and drive the interleaving with a `threading.Barrier` (both threads have
read before either writes) or `threading.Event`s (thread B starts only once A
is inside). That turns the race into a deterministic test. The fix is to make
the read and the write one critical section under a `threading.Lock`.
"""

import threading
from typing import Callable

Hook = Callable[[], None]


class Account:
    def __init__(self) -> None:
        self.balance = 0
        self.lock = threading.Lock()


def deposit_unsafe(account: Account, amount: int, between: Hook) -> None:
    current = account.balance           # read
    between()                           # another thread may run here
    account.balance = current + amount  # write


def deposit_locked(account: Account, amount: int, between: Hook) -> None:
    with account.lock:
        current = account.balance
        between()
        account.balance = current + amount


def run_pair(target: Callable[[], None], other: Callable[[], None]) -> None:
    threads = [threading.Thread(target=target), threading.Thread(target=other)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)


def noncompliant(rounds: int) -> tuple[int, int]:
    lost = 0
    last = 0
    for _ in range(rounds):
        account = Account()
        both_read = threading.Barrier(2, timeout=5)
        run_pair(lambda: deposit_unsafe(account, 100, both_read.wait),
                 lambda: deposit_unsafe(account, 100, both_read.wait))
        last = account.balance
        lost += account.balance != 200
    return lost, last


def compliant(rounds: int) -> tuple[int, int, int]:
    lost = 0
    last = 0
    blocked = 0
    for _ in range(rounds):
        account = Account()
        a_inside = threading.Event()
        b_ready = threading.Event()
        seen_locked: list[bool] = []

        def a_between() -> None:
            a_inside.set()           # A has read and holds the lock...
            b_ready.wait(timeout=5)  # ...and stays inside until B tries to enter

        def thread_b() -> None:
            a_inside.wait(timeout=5)
            seen_locked.append(account.lock.locked())
            b_ready.set()
            deposit_locked(account, 100, lambda: None)  # blocks until A is done

        run_pair(lambda: deposit_locked(account, 100, a_between), thread_b)
        last = account.balance
        lost += account.balance != 200
        blocked += seen_locked == [True]
    return lost, last, blocked


def main() -> None:
    lost, last = noncompliant(50)
    print(f"noncompliant: 50 rounds of 2 x deposit(100): {lost} lost updates, last balance {last}")
    lost, last, blocked = compliant(50)
    print(f"compliant:    50 rounds of 2 x deposit(100): {lost} lost updates, last balance {last}")
    print(f"compliant:    thread B found the lock held in {blocked}/50 rounds and waited")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: 50 rounds of 2 x deposit(100): 50 lost updates, last balance 100
# compliant:    50 rounds of 2 x deposit(100): 0 lost updates, last balance 200
# compliant:    thread B found the lock held in 50/50 rounds and waited
