# NativeForensics app icon

Original vector artwork: a watchful dark hound, amber muzzle, and teal magnifying
glass on a navy macOS tile. The investigation motif is inspired by the forensic
workflow; the artwork does not include or reproduce the Autopsy logo.

`AppIcon.png` is the 1024-pixel master. `AppIcon.icns` includes 16, 32, 128, 256,
and 512 point representations at 1× and 2× scale. Small representations omit the
lens glint to preserve the silhouette.

Regenerate both committed assets from the repository root on macOS:

```sh
swift script/generate_app_icon.swift Assets/AppIcon
```

The app bundle copies `AppIcon.icns` into `Contents/Resources` and references it
through `CFBundleIconFile`. Welcome and sidebar imagery can use the bundled app
icon without a separate artwork resource.
