from utils.misc import extract_name
import os
from collections import defaultdict
import re
from matplotlib import pyplot as plt
import numpy as np


def collect_usage(output_dir):

    n_used_list = []
    total_list = []
    dir_list = os.listdir(output_dir)
        # sort the directories
    dir_list.sort()

    for dir_name in dir_list:
        if not os.path.isdir(os.path.join(output_dir, dir_name)):
            print(f"{dir_name} is not a directory")
            continue

        work_dir = os.path.join(output_dir, dir_name)

        # read the agent.log
        log_file = os.path.join(work_dir,  "agent.log")
        func_sig_path = os.path.join(work_dir, "function.txt")

        with open(func_sig_path, "r") as f:
            function_signature = f.read()
            function_name = extract_name(function_signature)

        if not os.path.exists(log_file):
            print(f"{log_file} does not exist")
            continue


        with open(log_file, "r") as f:
            log_lines = f.read()

        project_name = dir_name.split("_")[0]
        log_prefix = f"{project_name}-{function_name}"

        total_usage_pattern = r"Found (\d+) usage"
        used_usage_pattern = r"only use (\d+) examples."
        # count the no usage case
        total_match = re.search(total_usage_pattern, log_lines)
        if total_match:
            total_usage = int(total_match.group(1))
            total_list.append(total_usage)
        else:
            print(f"total usage not found in {log_file}")
            continue

        used_match = re.search(used_usage_pattern, log_lines)
        if used_match:
            used_usage = int(used_match.group(1))
            n_used_list.append(used_usage)
        else:
            n_used_list.append(total_usage)
            continue

    return n_used_list, total_list

def plot_usage(n_used_list, total_list):


    # Create histogram
    plt.hist(total_list, bins=30, edgecolor='black')
    plt.xlabel('Total Examples')
    plt.ylabel('# of Functions')
    plt.title(f'Strategy: random selection, maximize the number of examples')
    plt.savefig(f"example_distribution.png")
    plt.show()
    # 
    n_used_list = np.array(n_used_list)
    total_list = np.array(total_list) + 1e-10  # Avoid division by zero
    # Calculate the ratio
    ratio = n_used_list / total_list
    # Create histogram
    plt.hist(ratio, bins=30, edgecolor='black')
    plt.xlabel('Ratio of # used example to # total examples')
    plt.ylabel('# of Functions')
    plt.title(f'Strategy: random selection, maximize the number of examples')
    plt.savefig(f"histogram_ratio.png")

    plt.show()


if __name__ == "__main__":

    n_used_list, total_list = collect_usage("/home/yk/code/LLM-reasoning-agents/outputs/issta_all_example/issta1")
    plot_usage(n_used_list, total_list)
