import sys

from soc_agent.errors import python_problem

if problem := python_problem():          # before anything imports Hermes (which fails on other versions)
    print(f"Setup error: {problem}", file=sys.stderr)
    sys.exit(2)

from soc_agent.cli import main  # noqa: E402

sys.exit(main())
