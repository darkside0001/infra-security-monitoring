# pg_dump/pg_restore must match the server major version (17).
# restic comes from its official image: pinned version, no package manager needed.
FROM restic/restic:0.18.0 AS restic
FROM postgres:17-alpine
COPY --from=restic /usr/bin/restic /usr/local/bin/restic
RUN mkdir -p /backup-repo /textfile && chown postgres:postgres /backup-repo /textfile
COPY --chmod=0755 backup.sh restore-test.sh restore.sh entrypoint.sh /usr/local/bin/
USER postgres
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
