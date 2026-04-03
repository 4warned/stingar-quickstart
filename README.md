# STINGAR quickstart

Interactive helper (`configure_stingar.py`) generates `stingar.env`, `nginx.conf`, and `docker-compose.yml` from `templates/`.

## Release alignment (v2.2.2)

`templates/docker-compose.yml.template` pins all `4warned/*` images to **`v2.2.2`**, matching the current production release layout used in **stingar-development** (`infra/terraform/docker-compose.yml.tpl`): same services, health checks, volumes, `nginx:alpine`, `redis:7-alpine`, and `stingarui` `STINGAR_ENV_PATH`.

To move to a newer release, edit the template and replace `v2.2.2` with the desired tag (and verify with release notes / `stingar-development` `VERSION`).

## Usage

```bash
python3 configure_stingar.py
docker compose up -d
```

Ensure `certs/` contains TLS material referenced by `nginx.conf`, and review `stingar.env` after generation.
