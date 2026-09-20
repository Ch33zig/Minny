"""The case file: saved forensic queries and the document they assemble.

    from minny.casefile import queries, build

`queries` holds one named, re-runnable function per claim; `build` turns their
results into `data/case_file.json`. Importing this package pulls in neither,
so a module that only wants one of them pays for one of them.
"""
