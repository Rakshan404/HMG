# HMG — HTTP DVR/NVR Decoy

## Install

Use Python 3.10 or newer. From the project root, install dependencies:

```sh
python -m pip install -r requirements.txt
```

## Run

Start the decoy with `python -m decoys.http.app`, then open http://127.0.0.1:8080/. The default runner uses `config.py` values and binds to loopback only. Alternate deployment runners must also be configured to bind to `127.0.0.1`; the Flask app factory does not enforce network binding. Login attempts always fail; no real device or authentication service is contacted. Structured JSON event records are written to standard error/output via Python logging. Records include timestamp, source IP, user agent, endpoint, and username; passwords are never recorded.

## Tests

Install pytest with `python -m pip install pytest`, then run `python -m pytest tests/test_http.py` from the project root.

The empty `decoys/smb/` directory is reserved for later work; no SMB implementation is included.
