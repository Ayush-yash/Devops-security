import re
import logging
import os

# Configure logging for the log analyzer
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger("LogParser")

# Regex to parse log lines (supports ISO timestamps, brackets, dashes, etc.)
LOG_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'  # Timestamp
    r'(?:\[|--\s*|Level:\s*|\-\s*)?'                             # Optional separators
    r'(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)'             # Log level
    r'(?:\]|--\s*|\s*\-\s*)?\s+'                                 # Optional separators
    r'(.*)$',                                                    # Log message
    re.IGNORECASE
)

def parse_log_line(line):
    """
    Parses a single log line and returns a dictionary of fields if valid.
    Returns None if the line is malformed.
    """
    line_str = line.strip()
    if not line_str:
        return None
        
    match = LOG_PATTERN.match(line_str)
    if not match:
        logger.warning(f"Malformed log line skipped: '{line_str}'")
        return None
        
    timestamp, log_level, message = match.groups()
    return {
        "timestamp": timestamp,
        "log_level": log_level.upper(),
        "message": message.strip()
    }

def parse_log_file(file_path):
    """
    Parses a log file and returns structured log records as a list of dictionaries.
    """
    parsed_records = []
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")
        
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            record = parse_log_line(line)
            if record:
                parsed_records.append(record)
                
    return parsed_records

if __name__ == "__main__":
    # Sample logs to test the parser (contains valid formats and malformed/corrupted lines)
    sample_log_data = """2026-08-09 22:34:11 [INFO] Server started successfully
2026-08-09T22:34:15Z ERROR Database connection timeout (host: shieldops-db)
This is a corrupt line with no timestamp or level!
2026-08-09 22:34:20 - WARNING - Low memory threshold triggered
2026-08-09 22:34:25 [CRITICAL] OPA Admission Gate returned BLOCK status
Another malformed line - missing message
"""
    
    test_filename = "test_run.log"
    print(f"Creating temporary test log file: {test_filename}...")
    with open(test_filename, "w", encoding="utf-8") as f:
        f.write(sample_log_data)
        
    print("\nParsing log file...")
    try:
        results = parse_log_file(test_filename)
        
        print(f"\nSuccessfully parsed {len(results)} valid log records:")
        print("=" * 80)
        for r in results:
            print(r)
        print("=" * 80)
        
    finally:
        if os.path.exists(test_filename):
            os.remove(test_filename)
            print(f"\nTemporary test log file {test_filename} cleaned up.")
