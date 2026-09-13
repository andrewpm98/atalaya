.PHONY: help install dev api dashboard test lint fmt up down logs

help:
	@echo "Atalaya — comandos disponibles:"
	@echo "  make install    Instala dependencias (editable + dev)"
	@echo "  make api        Levanta la API en local (sin Docker)"
	@echo "  make dashboard  Levanta el dashboard Streamlit en local"
	@echo "  make test       Ejecuta la batería de tests"
	@echo "  make lint       Linter (ruff) + tipos (mypy)"
	@echo "  make fmt        Formatea el código (ruff format)"
	@echo "  make up         Levanta todo el stack con docker-compose"
	@echo "  make down       Detiene el stack"
	@echo "  make logs       Muestra logs del stack"

install:
	pip install -e ".[dev]"

api:
	uvicorn atalaya.api.main:app --reload --host 0.0.0.0 --port 8000

dashboard:
	streamlit run dashboard/app.py

test:
	pytest -q

lint:
	ruff check src tests
	mypy src

fmt:
	ruff format src tests dashboard

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f
