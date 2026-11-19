#!/bin/sh
set -eu

HOST=${HOST:-root@10.172.10.34}
TREX_HOME=${TREX_HOME:-/opt/v3.07}
PYTHON=${PYTHON:-/opt/trex-python/bin/python3}
PREFIX=${PREFIX:-/opt/mhddos-trex}
REPO=$(cd "$(dirname "$0")/.." && pwd)
MHDDOS_DIR=${MHDDOS_DIR:-$REPO/../MHDDoS}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test -f "$MHDDOS_DIR/start.py" || { echo "MHDDoS checkout not found at $MHDDOS_DIR (set MHDDOS_DIR)" >&2; exit 1; }

cat > "$WORK/mhddos-trex" <<EOF
#!/bin/sh
set -eu
export PYTHONPATH=$PREFIX/lib:$TREX_HOME/automation/trex_control_plane/interactive:$TREX_HOME/external_libs/scapy-2.4.3\${PYTHONPATH:+:\$PYTHONPATH}
export MHDDOS_DIR=$PREFIX/MHDDoS
exec $PYTHON -W ignore -m mhddos_trex "\$@"
EOF
chmod 755 "$WORK/mhddos-trex"

tar czf - -C "$REPO" --exclude=__pycache__ mhddos_trex pyproject.toml README.md \
  | ssh "$HOST" "mkdir -p $PREFIX/stage && tar xzf - -C $PREFIX/stage"

tar czf - -C "$MHDDOS_DIR" start.py files \
  | ssh "$HOST" "mkdir -p $PREFIX/MHDDoS && tar xzf - -C $PREFIX/MHDDoS"

scp -q "$WORK/mhddos-trex" "$HOST:/usr/local/bin/mhddos-trex"
scp -q "$REPO/docs/agent-usage-261119.md" "$HOST:$PREFIX/AGENT-USAGE.md"

ssh "$HOST" "set -eu
$PYTHON -m pip install --quiet --no-deps --no-build-isolation --root-user-action=ignore --upgrade --target $PREFIX/lib $PREFIX/stage
rm -rf $PREFIX/stage
/usr/local/bin/mhddos-trex list > /dev/null
echo \"deployed to $HOST:$PREFIX\""
