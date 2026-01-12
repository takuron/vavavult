import datetime
import sys


def main():
    """
    Appends a log message with a timestamp to the llm_log.txt file.

    The log message is taken from the first command-line argument.
    """
    if len(sys.argv) < 2:
        print("Error: No log message provided.", file=sys.stderr)
        print('Usage: python llm_log.py "Your log message"', file=sys.stderr)
        sys.exit(1)

    log_message = sys.argv[1]
    # Get a timezone-aware local datetime object and format it as an ISO 8601 string
    timestamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    formatted_log = f"[{timestamp}] {log_message}"

    try:
        # Use 'llm_log.txt' as requested by the user
        with open("llm_log.txt", "a", encoding="utf-8") as f:
            f.write(formatted_log + "\n")
        print(f"Successfully logged to llm_log.txt: {formatted_log}")
    except IOError as e:
        print(f"Error writing to log file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
