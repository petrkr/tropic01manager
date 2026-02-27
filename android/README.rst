Tropic01 Android POC
====================

Scope
-----

- First rough project for Android with Python runtime.
- Transport support: ``TCP`` and ``Network`` only.
- Goal: verify ``tropicsquare`` usage on Android path before full app migration.

Current Layout
--------------

- ``main.py``: Kivy UI for connection, ``chipid``, and secure session actions.
- ``app/services/tropic_client.py``: transport + TropicSquare wrapper (TCP/Network + session start/abort).
- ``app/services/settings_store.py``: persistent settings via ``JsonStore``.
- ``buildozer.spec``: minimal packaging config.

Local Run (desktop smoke test)
------------------------------

Use venv only:

.. code-block:: bash

   python -m venv .venv
   source .venv/bin/activate
   pip install kivy buildozer
   python main.py

Android Build (initial)
-----------------------

.. code-block:: bash

   source .venv/bin/activate
   buildozer android debug

Notes
-----

- ``main.py`` temporarily adds repository root to ``sys.path`` for local import.
- For standalone APK, include ``tropicsquare`` inside Android project source.
- Connection and pairing form values are persisted in app sandbox ``user_data_dir/settings.json``.
- USB/UART support is intentionally postponed after TCP/Network validation.
