"""Testing beyond the examples — the author's own examples are not a test suite

https://docs.python.org/3/library/unittest.html

Write a function and its tests in one go and you get code plus examples
that agree with each other, because both come from the same head with the
same blind spot. `merge_intervals` below passes all three of its own tests
and is still wrong: it does not merge intervals that only touch, [1, 3] and
[3, 5].

Write the tests from the specification instead: compare against a slow but
obviously correct reference, on many random inputs from a *seeded*
`random.Random`, so a failure is reproducible by seed. Shrink the failing input
by deleting elements while it still fails, and the report shows the smallest
counterexample instead of a wall of numbers. unittest's runner prints timings,
so the demo collects results itself.
"""

import random
import unittest


def merge_intervals_naive(intervals: list[list[int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def merge_intervals_fixed(intervals: list[list[int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:  # closed intervals: touching overlaps
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def reference(intervals: list[list[int]]) -> list[list[int]]:
    """Slow and obvious: keep merging any two overlapping intervals."""
    spans = [list(i) for i in intervals]
    changed = True
    while changed:
        changed = False
        for i in range(len(spans)):
            for j in range(i + 1, len(spans)):
                (a, b), (c, d) = spans[i], spans[j]
                if a <= d and c <= b:
                    spans[i] = [min(a, c), max(b, d)]
                    del spans[j]
                    changed = True
                    break
            if changed:
                break
    return sorted(spans)


def random_case(rng: random.Random) -> list[list[int]]:
    case = []
    for _ in range(rng.randint(0, 6)):
        start = rng.randint(0, 12)
        case.append([start, start + rng.randint(0, 4)])
    return case


def shrink(case: list[list[int]], fails) -> list[list[int]]:
    smaller = True
    while smaller:
        smaller = False
        for i in range(len(case)):
            candidate = case[:i] + case[i + 1:]
            if fails(candidate):
                case, smaller = candidate, True
                break
    return case


def make_suite(merge) -> type[unittest.TestCase]:
    class MergeTests(unittest.TestCase):
        # The three examples written together with the function.
        def test_author_examples(self) -> None:
            self.assertEqual(merge([[1, 3], [2, 6], [8, 10]]), [[1, 6], [8, 10]])
            self.assertEqual(merge([[1, 4], [0, 2]]), [[0, 4]])
            self.assertEqual(merge([]), [])

        def test_matches_reference_seeded(self) -> None:
            def fails(case: list[list[int]]) -> bool:
                return merge([list(i) for i in case]) != reference(case)

            for seed in range(300):
                case = random_case(random.Random(seed))
                if fails(case):
                    small = shrink(case, fails)
                    self.fail(f"seed={seed} minimal={small} got={merge(small)} "
                              f"want={reference(small)}")

        def test_does_not_modify_input(self) -> None:
            for seed in range(50):
                case = random_case(random.Random(seed))
                before = [list(i) for i in case]
                merge(case)
                self.assertEqual(case, before, f"seed={seed}")

    MergeTests.__name__ = f"MergeTests[{merge.__name__}]"
    return MergeTests


def run(test_case: type[unittest.TestCase]) -> None:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_case)
    names = [test.id().rsplit(".", 1)[-1] for test in suite]  # suite.run() drops its tests
    result = unittest.TestResult()
    suite.run(result)
    failed = {test.id().rsplit(".", 1)[-1]: msg for test, msg in result.failures + result.errors}
    print(f"{test_case.__name__}: {result.testsRun} tests, {len(failed)} failed")
    for name in names:
        if name in failed:
            print(f"  FAIL {name}: {failed[name].strip().splitlines()[-1]}")
        else:
            print(f"  ok   {name}")


def main() -> None:
    run(make_suite(merge_intervals_naive))
    run(make_suite(merge_intervals_fixed))


if __name__ == "__main__":
    main()

# Output:
# MergeTests[merge_intervals_naive]: 3 tests, 1 failed
#   ok   test_author_examples
#   ok   test_does_not_modify_input
#   FAIL test_matches_reference_seeded: AssertionError: seed=2 minimal=[[0, 0], [0, 4]] got=[[0, 0], [0, 4]] want=[[0, 4]]
# MergeTests[merge_intervals_fixed]: 3 tests, 0 failed
#   ok   test_author_examples
#   ok   test_does_not_modify_input
#   ok   test_matches_reference_seeded
