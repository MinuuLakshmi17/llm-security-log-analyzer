import os
# Isolated DB for the test suite. Must be set before any app.* import,
# because the engine and settings are created at import time.
os.environ["DATABASE_URL"]="sqlite:////tmp/llmsec_test.db"
if os.path.exists("/tmp/llmsec_test.db"):
    os.remove("/tmp/llmsec_test.db")
