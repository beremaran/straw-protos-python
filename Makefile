.PHONY: check generate

check:
	uv run --frozen python -m unittest discover tests
	uv build --no-sources

generate:
	test -n "$(SOURCE_DIR)"
	buf generate "$(SOURCE_DIR)" --template buf.gen.yaml
