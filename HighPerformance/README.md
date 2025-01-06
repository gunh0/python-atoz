# HighPerformance

Reading notes for *High Performance Python, 2nd Edition* (Micha Gorelick and Ian Ozsvald, O'Reilly, 2020). The notebooks follow chapter 2, *Profiling to Find Bottlenecks*, which uses a Julia set generator as the CPU-bound workload to measure.

| File | What it covers |
| --- | --- |
| [01_calculating-the-full-julia-set](01_calculating-the-full-julia-set.ipynb) | The pure-Python Julia set: build the complex grid, run the update rule `z = z * z + c` per point, draw the result with matplotlib |
| [02_simple-approaches-to-timing-print-and-a-decorator](02_simple-approaches-to-timing-print-and-a-decorator.ipynb) | Timing with `time.time()` around the call, then the same measurement moved into a `@timefn` decorator with `functools.wraps` |
| [03_run_timeit](03_run_timeit.ipynb) | Timing the whole run from the command line with `python -m timeit` |
| [julia1_nopil.py](julia1_nopil.py) | The module that `03_run_timeit` imports: the notebook code as one file with the decorator applied |

## Notes

- The workload is a 1000 x 1000 grid with at most 300 iterations per point, so `calculate_z_serial_purepython` evaluates the update rule up to 300 million times. On my laptop it took about 3.6–3.7 s in pure Python, whether timed with `print`, the decorator or `timeit`.
- Measure before optimising. The first thing chapter 2 does is establish a baseline number, because without one there is no way to tell whether a later change helped.
- A timing decorator is convenient but adds a function call and a `print` to every call it wraps. That is fine for a function that runs once for seconds, and misleading for one that is called millions of times.
- `functools.wraps` keeps `__name__` and the docstring of the wrapped function, which is why the decorator can print `calculate_z_serial_purepython` instead of `measure_time`.
- `time.time()` is wall-clock time and can jump when the system clock is adjusted. For measuring intervals, `time.perf_counter()` is the better choice.
- `python -m timeit -n 5 -r 1 -s "import julia1_nopil" "julia1_nopil.calc_pure_python(desired_width=1000, max_iterations=300)"` runs the statement 5 times in one repetition and reports the best per-loop time. The `-s` setup import is not part of the measurement.
- Under `timeit` the module runs in a plain subprocess with no notebook to draw into, so `plt.show()` displays nothing. Only the printed timings matter there.

## Running

The notebooks were written on Python 3.11 and need NumPy and matplotlib from the root [`requirements.txt`](../requirements.txt). They are not part of `scripts/check.py`: their output is timing numbers, which change on every run.

```bash
python3 -m venv ./venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` includes `ipykernel`, so the venv can be selected as the kernel in VS Code or JupyterLab.
