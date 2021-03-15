MODULE := fabular

pkg: readme
	@pipenv run python setup.py sdist bdist_wheel

dev: readme
	@pipenv install --dev
	@pipenv install -e .

readme:
	@emacs --batch readme_src.org -f org-md-export-to-markdown
	@mv readme_src.md README.md

prereq:
	@pip install pipenv

test: pytest bandit

pytest:
	@pipenv run pytest -v --cov=fabular --cov-report=html

bandit:
	@pipenv run bandit src/ tests/ -r

clean:
	rm -rf .pytest_cache .coverage htmlcov README.md dist build
