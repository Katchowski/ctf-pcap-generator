.PHONY: build run test lint shell stop clean

build:
	docker compose build

run:
	docker compose up

test:
	docker compose run --rm web uv run pytest

lint:
	docker compose run --rm web uv run ruff check .
	docker compose run --rm web uv run ruff format --check .

shell:
	docker compose run --rm web /bin/bash

stop:
	docker compose down

clean:
	docker compose down -v --rmi local
