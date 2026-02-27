[app]
title = Tropic01 Android POC
package.name = tropic01poc
package.domain = com.example
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,rst,txt
source.exclude_dirs = .buildozer,bin,venv,.venv,__pycache__
version = 0.1.0
requirements = python3,kivy,cryptography==2.9.2
p4a.branch = v2024.01.21
android.permissions = INTERNET
orientation = portrait
fullscreen = 1

[buildozer]
log_level = 2
warn_on_root = 1
