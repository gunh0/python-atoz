# Fluent

Reading notes for *Fluent Python, 2nd Edition* (Luciano Ramalho, O'Reilly, 2022), one Jupyter notebook per book example. The goal is to work through the book with the code in front of me, not to reproduce it: each notebook keeps the example short and adds what I noticed while running it.

| Notebook | Chapter | What it covers |
| --- | --- | --- |
| [01-01_a-deck-as-a-sequence-of-playing-cards](01-the-python-data-model/01-01_a-deck-as-a-sequence-of-playing-cards.ipynb) | 1. The Python Data Model | `collections.namedtuple` for a `Card`, and a `FrenchDeck` that implements only `__len__` and `__getitem__` |

## Notes

### 1. The Python Data Model

- A class does not need to inherit from anything to behave like a built-in collection. Implementing `__len__` and `__getitem__` is enough for `len(deck)`, `deck[0]`, `deck[-1]` and slicing to work.
- Because `__getitem__` delegates to a list, iteration, `in`, `random.choice(deck)`, `sorted(deck, key=...)` and `reversed(deck)` come for free. Python falls back to the sequence protocol when there is no `__iter__` or `__contains__`.
- Special methods are called by the interpreter, not by me. Writing `len(deck)` instead of `deck.__len__()` is the point: built-ins can take fast paths and the class stays usable with the rest of the language.
- `namedtuple` gives a readable `repr` (`Card(rank='7', suit='diamonds')`), field access and tuple behaviour without writing a class body.

## Running

The notebooks were written on Python 3.11 with the packages in the root [`requirements.txt`](../requirements.txt). They are not part of `scripts/check.py`, which only runs the single-file examples in `sysadmin/`, `security/` and `practice/`.

```bash
python3 -m venv ./venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` includes `ipykernel`, so the venv can be selected as the kernel in VS Code or JupyterLab.
