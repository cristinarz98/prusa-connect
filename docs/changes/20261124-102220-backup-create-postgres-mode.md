### Fixed
- `prusa-connect backup create` now uses the PostgreSQL backup mode set in `core.upgrade.postgres_backup`, as `backup restore` already did. When the database is left out of the backup, its error names `-postgres pg_dump`, the configuration key and `-acknowledge-external-postgres`.
