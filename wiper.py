import os
import secrets
import string
import argparse
import sys

def secure_wipe_file(file_path, passes=3):
    """
    Securely overwrite a file with multiple patterns, rename it, truncate it, and delete it.
    
    :param file_path: Path to the file to be wiped.
    :param passes: Number of overwrite passes (default: 3).
    """
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    file_size = os.path.getsize(file_path)
    print(f"File Path: {file_path}")
    print(f"File Size: {file_size} bytes")

    try:
        # Overwrite the file with multiple patterns
        patterns = [b'\x00', b'\xFF', os.urandom]
        for pass_num in range(1, passes + 1):
            with open(file_path, 'r+b') as f:
                pattern = patterns[(pass_num - 1) % len(patterns)]
                if callable(pattern):
                    print(f"Pass {pass_num}: Writing random data...")
                    f.write(pattern(file_size))
                else:
                    print(f"Pass {pass_num}: Writing pattern {pattern}...")
                    f.write(pattern * file_size)
                f.flush()
                os.fsync(f.fileno())

        # Rename the file to a random string
        random_name = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        random_path = os.path.join(os.path.dirname(file_path), random_name)
        os.rename(file_path, random_path)

        # Truncate the file
        with open(random_path, 'w') as f:
            f.truncate(0)

        # Delete the file
        os.remove(random_path)
        print(f"File {file_path} has been securely wiped.")

    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    """
    Parse command-line arguments and securely wipe the specified file.
    """
    parser = argparse.ArgumentParser(description="Securely overwrite a file to prevent recovery.")
    parser.add_argument("file_path", help="Path to the file to be wiped")
    parser.add_argument("-p", "--passes", type=int, default=3, help="Number of overwrite passes (default: 3)")
    
    args = parser.parse_args()
    
    try:
        secure_wipe_file(args.file_path, args.passes)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
