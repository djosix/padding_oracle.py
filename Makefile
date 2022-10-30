.PHONY: build upload test

build:
	python3 -m pip install --upgrade build
	python3 -m build

upload:
	python3 -m pip install --upgrade twine
	python3 -m twine upload --repository pypi dist/*

test:
	python3 -m pip install --upgrade --requirement requirements.txt
	python3 -m pytest tests
