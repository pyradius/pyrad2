.PHONY: all call-submake

ARGS ?=

mypy: 
	uv run mypy pyrad2 $(ARGS)

test:
	uv run pytest --cov=pyrad2 --cov-report=term --ignore=tests/conformance tests/ $(ARGS)

# FreeRADIUS interop conformance: parses upstream FreeRADIUS dictionaries
# and decodes packet test vectors. Excluded from `make test` because the
# corpus is fetched on demand (gitignored); run these targets together
# for the interop signal.
conformance-fetch:
	uv run python scripts/fetch_freeradius_corpus.py

conformance-test:
	uv run pytest tests/conformance/ $(ARGS)


serve_docs:
	uv run mkdocs serve
	
deploy_docs:
	uv run mkdocs gh-deploy

status:
	PYTHONPATH=. uv run examples/status.py

server:
	PYTHONPATH=. uv run examples/server.py

server_async:
	PYTHONPATH=. uv run examples/server_async.py

server_radsec:
	PYTHONPATH=. uv run examples/server_radsec.py

server_coa:
	PYTHONPATH=. uv run examples/server_coa.py 3799

#
# RADIUS Client 
#
auth:
	PYTHONPATH=. uv run examples/auth.py

auth_radsec:
	PYTHONPATH=. uv run examples/auth_radsec.py

auth_async:
	PYTHONPATH=. uv run examples/auth_async.py

acct:
	PYTHONPATH=. uv run examples/acct.py

acct_radsec:
	PYTHONPATH=. uv run examples/acct_radsec.py

coa:
	PYTHONPATH=. uv run examples/client_coa.py coa daemon-1234

status_radsec:
	PYTHONPATH=. uv run examples/status_radsec.py

dictionary_features:
	PYTHONPATH=. uv run examples/dictionary_features.py

#
# Scenarios — single-process end-to-end demos (see scenarios/README.md)
#
scenario_auth:
	uv run python scenarios/auth.py

scenario_acct:
	uv run python scenarios/acct.py

scenario_coa:
	uv run python scenarios/coa.py

scenario_status:
	uv run python scenarios/status.py

scenario_dedup:
	uv run python scenarios/dedup.py

scenario_radsec:
	uv run python scenarios/radsec_auth.py

scenario_radsec_v11:
	uv run python scenarios/radsec_v11.py

demo: scenario_auth scenario_acct scenario_coa scenario_status scenario_dedup scenario_radsec scenario_radsec_v11