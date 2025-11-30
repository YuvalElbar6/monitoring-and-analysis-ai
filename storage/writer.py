
import os

from os_env import EVENTS_DIR, OUTPUT_FILE_NAME


os.makedirs(EVENTS_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(EVENTS_DIR, OUTPUT_FILE_NAME)


def write_event(event):
    with open(OUTPUT_FILE, 'a') as f:
        f.write(event.model_dump_json() + "\n")