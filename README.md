# STINGAR quickstart

Interactive helper (`configure_stingar.py`) generates `stingar.env`, `nginx.conf`, and `docker-compose.yml` from `templates/`.

## Release v2.3

Pins all `4warned/*` images to **`v2.3`**, matching the current production release layout.

To move to a newer release, edit the template and replace `v2.3` with the desired tag (and verify with release notes / `stingar-development` `VERSION`).

## Usage

```bash
python3 configure_stingar.py
docker compose up -d
```

Ensure `certs/` contains TLS material referenced by `nginx.conf`, and review `stingar.env` after generation.
