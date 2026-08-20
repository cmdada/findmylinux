#!/usr/bin/env python3
"""A libadwaita front-end for findmylinux: map, service status, and history.

pretty much all my logic is in findmylinux.py, this reuses its fetch/decrypt path
and just presents it. Network fetches run on a worker thread and marshal back to
the main loop with GLib.idle_add
"""

import subprocess
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Shumate", "1.0")
from gi.repository import Adw, Gio, GLib, Gtk, Shumate

import findmylinux

APP_ID = "org.adabit.FindMyLinux"
REFRESH_SECONDS = 300
DEFAULT_ZOOM = 16

SERVICES = [
    ("Advertising", "findmylinux.service", "system"),
    ("Anisette", "findmylinux-anisette.service", "user"),
    ("Location daemon", "findmylinux-location.service", "user"),
]


def run_in_thread(work, on_done):
    """Run work() off the main loop, then call on_done(result, error) on it."""
    def target():
        try:
            result, error = work(), None
        except Exception as exc:
            result, error = None, exc
        GLib.idle_add(on_done, result, error)

    threading.Thread(target=target, daemon=True).start()


def systemctl(scope, *args, root=False):
    cmd = ["systemctl"] + (["--user"] if scope == "user" else []) + list(args)
    if root and scope == "system":
        cmd = ["pkexec"] + cmd
    return subprocess.run(cmd, capture_output=True, text=True)


def service_active(scope, unit):
    return systemctl(scope, "is-active", unit).stdout.strip() == "active"


def relative_age(timestamp):
    seconds = max(0, int(time.time() - timestamp))
    if seconds < 90:
        return f"{seconds}s ago"
    if seconds < 5400:
        return f"{seconds // 60} min ago"
    if seconds < 172800:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Find My Linux")
        self.set_default_size(980, 660)
        self.fixes = []
        self.service_rows = {}
        self._tried_autostart = False

        split = Adw.OverlaySplitView(min_sidebar_width=320, max_sidebar_width=380)
        self.set_content(split)
        split.set_sidebar(self._build_sidebar())
        split.set_content(self._build_map_pane())

        for name, handler in (("signin", lambda *_: self._sign_in()),
                              ("signout", lambda *_: self._sign_out()),
                              ("settings", lambda *_: self._settings())):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

        self.refresh()
        GLib.timeout_add_seconds(REFRESH_SECONDS, self._auto_refresh)

        # Refresh the moment the location daemon writes a new fix, rather than
        # only on the timer — /etc/geolocation changes exactly once per update.
        geo_file = Gio.File.new_for_path(str(findmylinux.GEOLOCATION_FILE))
        self._geo_monitor = geo_file.monitor_file(Gio.FileMonitorFlags.NONE, None)
        self._geo_monitor.connect("changed", self._on_geo_changed)


    def _build_sidebar(self):
        header = Adw.HeaderBar()
        self.spinner = Gtk.Spinner()
        self.refresh_button = Gtk.Button(icon_name="view-refresh-symbolic",
                                         tooltip_text="Refresh")
        self.refresh_button.connect("clicked", lambda _b: self.refresh())
        header.pack_start(self.refresh_button)
        header.pack_end(self.spinner)
        header.set_title_widget(Adw.WindowTitle(title="Find My Linux",
                                                subtitle="Use Find My's network as your gps"))

        page = Adw.PreferencesPage()

        status_group = Adw.PreferencesGroup(title="Services")
        for label, unit, scope in SERVICES:
            row = Adw.ActionRow(title=label, subtitle="checking…")
            dot = Gtk.Image(icon_name="media-record-symbolic")
            dot.add_css_class("dim-label")
            row.add_prefix(dot)
            switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            switch.connect("state-set", self._on_toggle, scope, unit)
            row.add_suffix(switch)
            row.set_activatable_widget(switch)
            self.service_rows[unit] = (row, dot, switch)
            status_group.add(row)
        page.add(status_group)

        loc_group = Adw.PreferencesGroup(title="Latest location")
        self.coord_row = Adw.ActionRow(title="No fix yet", subtitle="")
        self.coord_row.add_prefix(Gtk.Image(icon_name="find-location-symbolic"))
        open_button = Gtk.Button(icon_name="web-browser-symbolic",
                                 valign=Gtk.Align.CENTER,
                                 tooltip_text="Open in browser map")
        open_button.add_css_class("flat")
        open_button.connect("clicked", self._open_in_browser)
        self.coord_row.add_suffix(open_button)
        loc_group.add(self.coord_row)
        page.add(loc_group)

        self.history_group = Adw.PreferencesGroup(title="History")
        page.add(self.history_group)

        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER,
                                      vexpand=True, child=page)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(scroller)
        return toolbar


    def _build_map_pane(self):
        self.simple_map = Shumate.SimpleMap()
        registry = Shumate.MapSourceRegistry.new_with_defaults()
        self.simple_map.set_map_source(
            registry.get_by_id(Shumate.MAP_SOURCE_OSM_MAPNIK))

        self.marker_layer = Shumate.MarkerLayer.new(self.simple_map.get_viewport())
        self.simple_map.add_overlay_layer(self.marker_layer)

        self.toast_overlay = Adw.ToastOverlay(child=self.simple_map)

        map_header = Adw.HeaderBar()
        self.map_title = Adw.WindowTitle(title="", subtitle="")
        map_header.set_title_widget(self.map_title)
        menu = Gio.Menu()
        menu.append("Sign in to Apple ID…", "win.signin")
        menu.append("Sign out", "win.signout")
        menu.append("Settings…", "win.settings")
        menu.append("About Find My Linux", "app.about")
        map_header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic",
                                           menu_model=menu, tooltip_text="Menu"))

        self.login_banner = Adw.Banner(title="Sign in to your Apple ID to see "
                                       "the laptop's location",
                                       button_label="Sign in", revealed=False)
        self.login_banner.connect("button-clicked", lambda _b: self._sign_in())

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(map_header)
        toolbar.add_top_bar(self.login_banner)
        toolbar.set_content(self.toast_overlay)
        return toolbar

    def _set_marker(self, lat, lon, accuracy):
        self.marker_layer.remove_all()
        marker = Shumate.Marker()
        pin = Gtk.Image(icon_name="find-location-symbolic", pixel_size=32)
        pin.add_css_class("accent")
        marker.set_child(pin)
        marker.set_location(lat, lon)
        self.marker_layer.add_marker(marker)
        self.simple_map.get_viewport().set_zoom_level(DEFAULT_ZOOM)
        self.simple_map.get_map().center_on(lat, lon)


    def _auto_refresh(self):
        self.refresh()
        return GLib.SOURCE_CONTINUE

    def _on_geo_changed(self, _monitor, _file, _other, event):
        if event in (Gio.FileMonitorEvent.CHANGES_DONE_HINT,
                     Gio.FileMonitorEvent.CREATED):
            self.refresh()

    def refresh(self):
        self._refresh_services()

        if not findmylinux.apple_account().is_logged_in():
            self.login_banner.set_revealed(True)
            self.coord_row.set_title("Not signed in")
            self.coord_row.set_subtitle("Sign in to your Apple ID to fetch reports")
            return
        self.login_banner.set_revealed(False)

        self.spinner.start()
        self.refresh_button.set_sensitive(False)

        def work():
            return findmylinux.fetch_fixes("laptop", days=7)

        run_in_thread(work, self._on_fixes)


    def _sign_in(self):
        account = findmylinux.apple_account()
        if not account.anisette_reachable():
            self.toast_overlay.add_toast(Adw.Toast(
                title="Anisette isn't running — start findmylinux-anisette",
                timeout=5))
            return

        dialog = Adw.AlertDialog(
            heading="Sign in to Apple ID",
            body="Your password is sent only to Apple, never stored. "
                 "A verification code will be texted to your trusted number.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        apple_id = Gtk.Entry(placeholder_text="Apple ID (email)",
                             input_purpose=Gtk.InputPurpose.EMAIL)
        password = Gtk.PasswordEntry(show_peek_icon=True)
        password.set_property("placeholder-text", "Password")
        box.append(apple_id)
        box.append(password)
        dialog.set_extra_child(box)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("signin", "Sign in")
        dialog.set_response_appearance("signin", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("signin")

        def on_response(_dialog, response):
            if response != "signin":
                return
            username = apple_id.get_text().strip()
            secret = password.get_text()
            if username and secret:
                self._run_login(account, username, secret)

        dialog.connect("response", on_response)
        dialog.present(self)

    def _run_login(self, account, username, password):
        self.spinner.start()
        toast = Adw.Toast(title="Signing in…", timeout=0)
        self.toast_overlay.add_toast(toast)

        def work():
            account.login(username, password, self._ask_2fa_code)
            return True

        def done(_result, error):
            self.spinner.stop()
            toast.dismiss()
            if error is not None:
                dialog = Adw.AlertDialog(heading="Sign-in failed",
                                         body=str(error))
                dialog.add_response("ok", "OK")
                dialog.present(self)
            else:
                self.toast_overlay.add_toast(Adw.Toast(title="Signed in", timeout=3))
                self.refresh()

        run_in_thread(work, done)

    def _ask_2fa_code(self):
        """Called on the worker thread; blocks it until the user enters a code."""
        result = {}
        done = threading.Event()

        def show():
            dialog = Adw.AlertDialog(
                heading="Two-factor code",
                body="Enter the code texted to your trusted phone number.")
            entry = Gtk.Entry(input_purpose=Gtk.InputPurpose.DIGITS,
                             max_length=8)
            dialog.set_extra_child(entry)
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("verify", "Verify")
            dialog.set_response_appearance("verify", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_default_response("verify")

            def on_response(_dialog, response):
                result["code"] = entry.get_text().strip() if response == "verify" else ""
                done.set()

            dialog.connect("response", on_response)
            dialog.present(self)

        GLib.idle_add(show)
        done.wait()
        return result.get("code", "")

    def _sign_out(self):
        findmylinux.apple_account().logout()
        self.toast_overlay.add_toast(Adw.Toast(title="Signed out", timeout=3))
        self.refresh()

    def _settings(self):
        config = findmylinux.load_config()
        interval_min = config.get("interval", findmylinux.DEFAULT_INTERVAL) / 60
        window = config.get("triangulate_window", findmylinux.DEFAULT_WINDOW)

        dialog = Adw.AlertDialog(
            heading="Settings",
            body="How often to fetch location, and how far apart reports can be "
                 "and still be triangulated into one fix.")
        group = Adw.PreferencesGroup()
        interval_row = Adw.SpinRow.new_with_range(1, 120, 1)
        interval_row.set_title("Update every (minutes)")
        interval_row.set_value(interval_min)
        window_row = Adw.SpinRow.new_with_range(0, 600, 5)
        window_row.set_title("Triangulate window (seconds, 0 off)")
        window_row.set_value(window)
        group.add(interval_row)
        group.add(window_row)
        dialog.set_extra_child(group)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")

        def on_response(_dialog, response):
            if response != "save":
                return
            config["interval"] = int(interval_row.get_value() * 60)
            config["triangulate_window"] = int(window_row.get_value())
            findmylinux.save_config(config)
            run_in_thread(
                lambda: systemctl("user", "restart",
                                  "findmylinux-location.service"),
                lambda *_: self.refresh())
            self.toast_overlay.add_toast(Adw.Toast(title="Settings saved", timeout=3))

        dialog.connect("response", on_response)
        dialog.present(self)

    def _refresh_services(self):
        def work():
            return {unit: service_active(scope, unit)
                    for _label, unit, scope in SERVICES}

        run_in_thread(work, self._on_services)

    def _on_services(self, states, error):
        if error or states is None:
            return
        for _label, unit, _scope in SERVICES:
            row, dot, switch = self.service_rows[unit]
            active = states.get(unit, False)
            row.set_subtitle("active" if active else "inactive")
            dot.remove_css_class("success")
            dot.remove_css_class("dim-label")
            dot.add_css_class("success" if active else "dim-label")
            switch.handler_block_by_func(self._on_toggle)
            switch.set_active(active)
            switch.handler_unblock_by_func(self._on_toggle)

        if not self._tried_autostart and not states.get("findmylinux.service", False):
            self._tried_autostart = True
            self._control_advertising("start", lambda *_: self._refresh_services())

    def _on_fixes(self, fixes, error):
        self.spinner.stop()
        self.refresh_button.set_sensitive(True)

        if error is not None:
            self.toast_overlay.add_toast(Adw.Toast(title=str(error), timeout=5))
            return
        if not fixes:
            self.coord_row.set_title("No reports yet")
            self.coord_row.set_subtitle(
                "No Apple device has relayed the laptop, or it isn't advertising")
            return

        self.fixes = fixes
        timestamp, lat, lon, accuracy = fixes[0]
        self.coord_row.set_title(f"{lat:.6f}, {lon:.6f}")
        self.coord_row.set_subtitle(f"±{accuracy} m · {relative_age(timestamp)}")
        self.map_title.set_title(f"{lat:.5f}, {lon:.5f}")
        self.map_title.set_subtitle(f"±{accuracy} m · {relative_age(timestamp)}")
        self._set_marker(lat, lon, accuracy)
        self._rebuild_history()

    def _rebuild_history(self):
        for row in getattr(self, "_history_rows", []):
            self.history_group.remove(row)
        self._history_rows = []
        for timestamp, lat, lon, accuracy in self.fixes[:12]:
            when = time.strftime("%b %d  %H:%M", time.localtime(timestamp))
            row = Adw.ActionRow(title=when,
                                subtitle=f"{lat:.5f}, {lon:.5f}  ±{accuracy} m")
            row.set_activatable(True)
            row.connect("activated", self._on_history_activated, lat, lon)
            self.history_group.add(row)
            self._history_rows.append(row)


    def _on_history_activated(self, _row, lat, lon):
        self.simple_map.get_map().go_to_full(lat, lon, DEFAULT_ZOOM)

    def _open_in_browser(self, _button):
        if not self.fixes:
            return
        _t, lat, lon, _a = self.fixes[0]
        url = (f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}"
               f"#map=17/{lat:.6f}/{lon:.6f}")
        Gtk.UriLauncher(uri=url).launch(self, None, None, None)

    def _control_advertising(self, verb, on_finish):
        """Start/stop the system advertising service via pkexec, installing its
        unit into /etc/systemd/system first if systemd doesn't know it yet."""
        src = findmylinux.ROOT / "systemd"

        def work():
            script = (
                "if ! systemctl cat findmylinux.service >/dev/null 2>&1; then "
                f"install -Dm644 '{src}/findmylinux.service' "
                "/etc/systemd/system/findmylinux.service && "
                f"install -Dm644 '{src}/findmylinux-resume.service' "
                "/etc/systemd/system/findmylinux-resume.service && "
                "systemctl daemon-reload; fi; "
                f"systemctl {verb} findmylinux.service"
            )
            return subprocess.run(["pkexec", "/bin/sh", "-c", script],
                                  capture_output=True, text=True)

        run_in_thread(work, on_finish)

    def _on_toggle(self, switch, wanted, scope, unit):
        verb = "start" if wanted else "stop"
        switch.set_sensitive(False)

        def done(proc, error):
            switch.set_sensitive(True)
            if error or (proc and proc.returncode not in (0, 126)):
                message = (proc.stderr.strip() if proc else str(error)) or \
                    f"could not {verb} {unit}"
                self.toast_overlay.add_toast(Adw.Toast(title=message, timeout=5))
            self._refresh_services()

        if scope == "system":
            self._control_advertising(verb, done)
        else:
            run_in_thread(lambda: systemctl(scope, verb, unit), done)
        return True


class Application(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_startup(self):
        Adw.Application.do_startup(self)
        about = Gio.SimpleAction.new("about", None)
        about.connect("activate", self._on_about)
        self.add_action(about)

    def _on_about(self, _action, _param):
        dialog = Adw.AboutDialog(
            application_name="Find My Linux",
            application_icon="find-location-symbolic",
            developer_name="findmylinux",
            comments="Use Apple's Find My network for your system GPS location, with this GTK app for configuration and status",
            website="https://github.com/cmdada/findmylinux",
            license_type=Gtk.License.GPL_3_0)
        dialog.present(self.props.active_window)

    def do_activate(self):
        (self.props.active_window or Window(self)).present()


if __name__ == "__main__":
    Application().run(None)
