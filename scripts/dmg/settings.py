# dmgbuild settings for the Serbian eID Token DMG.
# Called by scripts/make-dmg.sh with -D app=<path/to/App.app> -D background=<tiff>.
# The layout (window size, icon positions) matches TokenApp/Design/dmg-background.svg (660x400).
import os.path

app = defines["app"]  # noqa: F821 (injected by dmgbuild)
app_name = os.path.basename(app)

format = "UDZO"
filesystem = "HFS+"
files = [app]
symlinks = {"Applications": "/Applications"}

icon = os.path.join(app, "Contents", "Resources", "AppIcon.icns")
background = defines["background"]  # noqa: F821

window_rect = ((200, 120), (660, 400))
default_view = "icon-view"
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False

icon_size = 112
text_size = 13
icon_locations = {
    app_name: (165, 190),
    "Applications": (495, 190),
}
hide_extensions = [app_name]
