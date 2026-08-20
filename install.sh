#!/bin/sh
set -e

SRC=$(cd "$(dirname "$0")" && pwd)
OWNER=${SUDO_USER:-${PKEXEC_UID:+$(id -un "$PKEXEC_UID")}}
: "${OWNER:=ada}"

if [ "$(id -u)" -ne 0 ]; then
	echo "run me through pkexec or run0" >&2
	exit 1
fi

ln -sf "$SRC/findmylinux.py" /usr/local/bin/findmylinux
install -m 644 "$SRC/systemd/findmylinux.service" /etc/systemd/system/
install -m 644 "$SRC/systemd/findmylinux-resume.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable findmylinux.service findmylinux-resume.service

if [ ! -e /etc/geolocation ]; then
	install -o "$OWNER" -g geoclue -m 640 /dev/null /etc/geolocation
fi

echo "installed."
echo "  start advertising : systemctl start findmylinux"
echo "  report side       : systemctl --user enable --now findmylinux-anisette; findmylinux login"
