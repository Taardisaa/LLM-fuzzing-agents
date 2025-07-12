import os

def remove_large_log_files(directory, size_limit_mb=10):
    size_limit_bytes = size_limit_mb * 1024 * 1024

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.log'):
                file_path = os.path.join(root, file)
                try:
                    if os.path.getsize(file_path) > size_limit_bytes:
                        print(f"Deleting: {file_path} (Size: {os.path.getsize(file_path)} bytes)")
                        os.remove(file_path)
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")

# Example usage
remove_large_log_files("/home/yk/code/LLM-reasoning-agents/outputs_ablation/example/project")
