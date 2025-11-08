from email.contentmanager import raw_data_manager
import matplotlib
matplotlib.use('Agg')  
import os
from collections import defaultdict
import re
from matplotlib import pyplot as plt
import numpy as np
from matplotlib_venn import venn2
import json
from pathlib import Path

# def collect_usage(output_dir):

#     n_used_list = []
#     total_list = []
#     dir_list = os.listdir(output_dir)
#         # sort the directories
#     dir_list.sort()

#     for dir_name in dir_list:
#         if not os.path.isdir(os.path.join(output_dir, dir_name)):
#             print(f"{dir_name} is not a directory")
#             continue

#         work_dir = os.path.join(output_dir, dir_name)

#         # read the agent.log
#         log_file = os.path.join(work_dir,  "agent.log")
#         func_sig_path = os.path.join(work_dir, "function.txt")

#         with open(func_sig_path, "r") as f:
#             function_signature = f.read()
#             function_name = extract_name(function_signature)

#         if not os.path.exists(log_file):
#             print(f"{log_file} does not exist")
#             continue


#         with open(log_file, "r") as f:
#             log_lines = f.read()

#         project_name = dir_name.split("_")[0]
#         log_prefix = f"{project_name}-{function_name}"

#         total_usage_pattern = r"Found (\d+) usage"
#         used_usage_pattern = r"only use (\d+) examples."
#         # count the no usage case
#         total_match = re.search(total_usage_pattern, log_lines)
#         if total_match:
#             total_usage = int(total_match.group(1))
#             total_list.append(total_usage)
#         else:
#             print(f"total usage not found in {log_file}")
#             continue

#         used_match = re.search(used_usage_pattern, log_lines)
#         if used_match:
#             used_usage = int(used_match.group(1))
#             n_used_list.append(used_usage)
#         else:
#             n_used_list.append(total_usage)
#             continue

#     return n_used_list, total_list

# def plot_usage(n_used_list, total_list):


#     # Create histogram
#     plt.hist(total_list, bins=30, edgecolor='black')
#     plt.xlabel('Total Examples')
#     plt.ylabel('# of Functions')
#     plt.title(f'Strategy: random selection, maximize the number of examples')
#     plt.savefig(f"example_distribution.png")
#     plt.show()
#     # 
#     n_used_list = np.array(n_used_list)
#     total_list = np.array(total_list) + 1e-10  # Avoid division by zero
#     # Calculate the ratio
#     ratio = n_used_list / total_list
#     # Create histogram
#     plt.hist(ratio, bins=30, edgecolor='black')
#     plt.xlabel('Ratio of # used example to # total examples')
#     plt.ylabel('# of Functions')
#     plt.title(f'Strategy: random selection, maximize the number of examples')
#     plt.savefig(f"histogram_ratio.png")

#     plt.show()

def venn_diagram(res_path1: Path, res_path2: Path, method1: str, method2: str):
    
    def get_projects(res_json: Path):
           
        with open(res_json, "r") as f:
            res_data = json.load(f)

        # Prepare arguments for multiprocessing
        args_list: list[str] = []
        for _, value in list(res_data.items()):
            args_list.append(value.get("project"))
        return set(args_list)

    A = get_projects(res_path1)
    B = get_projects(res_path2)

    # Compute counts
    only_A = len(A - B)
    only_B = len(B - A)
    both = len(A & B)

    print("Only in", method2, ":", sorted(list(B - A)))

    # Draw Venn diagram with counts
    venn = venn2(subsets=(only_A, only_B, both), set_labels=(method1, method2))

    # Customize labels (optional)
    venn.get_label_by_id('10').set_text(str(only_A))
    venn.get_label_by_id('01').set_text(str(only_B))
    venn.get_label_by_id('11').set_text(str(both))

    plt.savefig(f"{method1}_{method2}_venn.png", bbox_inches='tight')
    plt.close()

def violin_diagram():
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns

    # ---------------------------
    # Simulate final coverage for 4 fuzzing methods over 200 projects
    # ---------------------------
    np.random.seed(42)

    data = []
    methods = ["Method A", "Method B", "Method C", "Method D"]

    for m in methods:
        if m == "Method A":  # narrow distribution, low coverage
            cov = np.random.normal(20, 5, 200)
        elif m == "Method B":  # bimodal distribution (some succeed, some fail)
            cov = np.concatenate([np.random.normal(10, 3, 100), np.random.normal(40, 5, 100)])
        elif m == "Method C":  # wide spread
            cov = np.random.normal(25, 12, 200)
        else:  # Method D: consistent and high
            cov = np.random.normal(35, 4, 200)
        cov = np.clip(cov, 0, 50)  # clamp between 0–50%
        for c in cov:
            data.append((m, c))

    df = pd.DataFrame(data, columns=["method", "coverage"])

    # ---------------------------
    # Create side-by-side comparison figure
    # ---------------------------
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Histogram (left)
    sns.histplot(data=df, x="coverage", hue="method",
                bins=20, kde=False, multiple="stack", ax=axes[0])
    axes[0].set_title("Histogram: coverage distribution per method")
    axes[0].set_xlabel("Final coverage (%)")
    axes[0].set_ylabel("Number of projects")

    # Violin plot (right)
    sns.violinplot(data=df, x="method", y="coverage", inner="quartile", cut=0, ax=axes[1])
    axes[1].set_title("Violin plot: coverage shape & summary")
    axes[1].set_xlabel("Method")
    axes[1].set_ylabel("Final coverage (%)")

    plt.tight_layout()
    plt.savefig("hist_vs_violin.png", dpi=300)
    plt.show()

# violin_diagram()
our_path = Path("/home/yk/code/LLM-reasoning-agents/outputs_wild/gpt5-mini/agent/success_functions_3.json")
raw_path = Path("/home/yk/code/LLM-reasoning-agents/outputs_wild/gpt5-mini/issta/success_functions_3.json")
# raw_path = Path("/home/yk/code/fuzz-introspector/scripts/oss-fuzz-gen-e2e/workdir/oss-fuzz-gen/results/localFI/function0/success_functions_3.json")
venn_diagram(our_path, raw_path, "Agent", "ISSTA")

# if __name__ == "__main__":

    # n_used_list, total_list = collect_usage("/home/yk/code/LLM-reasoning-agents/outputs/issta_all_example/issta1")
    # plot_usage(n_used_list, total_list)
