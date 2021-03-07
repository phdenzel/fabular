MODULE := fabular

dev: readme
	@pipenv install --dev
	@pipenv install -e .

readme:
	@emacs --batch README.org -f org-md-export-to-markdown

prereq:
	@pip install pipenv

test:
	@pipenv run pytest -v --cov=fabular --cov-report=html

clean:
	rm -rf .pytest_cache .coverage htmlcov README.md
