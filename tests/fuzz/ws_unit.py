import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text()
source = source[source.index('/* WebSocket frame flags */'):]
source = source[:source.index('/* -------------------------------------------------------------------------\n * vtable')]
Path(sys.argv[2]).write_text(source)
