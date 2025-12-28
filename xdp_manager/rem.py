import os
import sys
import demoji

# Download/update the latest emoji list (does it automatically on first run)
demoji.download_codes()

def clean_filename(name):
    """Remove all emojis from a filename (keep the rest intact)"""
    return demoji.replace(string=name, repl="")  # repl="" removes them

def rename_recursively(root_dir, dry_run=True):
    renamed_count = 0
    for root, dirs, files in os.walk(root_dir):
        # Rename files
        for filename in files:
            new_filename = clean_filename(filename)
            if new_filename != filename:
                old_path = os.path.join(root, filename)
                new_path = os.path.join(root, new_filename)
                print(f"{'[DRY RUN] ' if dry_run else ''}Rename: {old_path} → {new_path}")
                if not dry_run:
                    os.rename(old_path, new_path)
                renamed_count += 1

        # Rename directories (bottom-up to avoid issues)
        for dirname in dirs:
            new_dirname = clean_filename(dirname)
            if new_dirname != dirname:
                old_path = os.path.join(root, dirname)
                new_path = os.path.join(root, new_dirname)
                print(f"{'[DRY RUN] ' if dry_run else ''}Rename dir: {old_path} → {new_path}")
                if not dry_run:
                    os.rename(old_path, new_path)
                renamed_count += 1

    print(f"\nTotal items renamed: {renamed_count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python remove_emojis_from_filenames.py /path/to/folder [--go]")
        print("  Add --go to actually perform renames (default is dry-run preview)")
        sys.exit(1)

    path = sys.argv[1]
    do_rename = "--go" in sys.argv

    print(f"Scanning: {os.path.abspath(path)}")
    print(f"Mode: {'ACTUAL RENAME' if do_rename else 'DRY RUN (preview only)'}\n")
    rename_recursively(path, dry_run=not do_rename)
