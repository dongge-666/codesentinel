# CodeSentinel Worker Skills

These packages are the reviewed source templates for P10-3. They are not
installed directly from an uncommitted working tree.

P10-3B must copy one package to an isolated Manager staging directory,
materialize `deployment-manifest.template.json` as `deployment-manifest.json`
with the accepted clean source revision and runtime-bundle reference/hash, and
then use the official Manager skill-management script with `--no-notify`.

Each staged package and its repository, MinIO, and Worker copies must have a
recorded tree hash. A template placeholder in a deployed package is a hard
failure.
