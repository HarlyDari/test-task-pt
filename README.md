Сервис на FastAPI для автоматической кластеризации Linux syslog-событий, снижения шума и обнаружения аномалий

# Структура

- `app/` — исходный код FastAPI приложения
- `data/` — пример логов
- `Dockerfile` — образ приложения
- `docker-compose.yml` — запуск сервиса в контейнере
- `requirements.txt` — зависимости Python

## Как запустить

1. Собрать образ и запустить контейнер:

```bash
docker compose up --build
```

2. Перейти к API:

- `http://localhost:8000/health`
- `http://localhost:8000/sample` - анализ примера
- `http://localhost:8000/docs` - Swagger UI

## API

- `POST /analyze` — анализировать загруженный файл или строку логов
  - поля: `file` (UploadFile), `raw_logs` (строка)
- `GET /sample` — анализ примера синтетического syslog

## Принцип работы

- `SyslogParser` разбирает строки syslog и нормализует сообщения
- `LogClusterer` векторизует текст и группирует с помощью DBSCAN
- `AnomalyDetector` помечает аномальные события как одиночные кластеры или шум
