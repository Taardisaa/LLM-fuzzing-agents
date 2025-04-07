import docker
from collections import defaultdict
import subprocess as sp
import os
from constants import LanguageType, PROJECT_PATH, DockerResults

class DockerUtils:

    def __init__(self, ossfuzz_dir: str, project_name: str, new_project_name: str, project_lang: str):
        self.image_name = "gcr.io/oss-fuzz/{}".format(new_project_name)
        self.ossfuzz_dir = ossfuzz_dir
        self.project_name = project_name
        self.new_project_name = new_project_name
        self.project_lang = project_lang

        # for CPP, the language is c++, other languages are the same as the project language
        self.FUZZING_LANGUAGE = project_lang.lower() if project_lang !=  LanguageType.CPP else "c++"


    def build_image(self, build_image_cmd: list[str]) -> bool:
        '''Build the image for the project'''
        try:
            sp.run(build_image_cmd, stdin=sp.DEVNULL, stdout=sp.DEVNULL, stderr=sp.STDOUT, check=True)
            return True
        except sp.CalledProcessError as e:
            return False



    def remove_image(self) -> None:
        """
        Remove the Docker image from the local machine.
        """
        try:
            client = docker.from_env()
            client.images.remove(self.image_name)
        except docker.errors.ImageNotFound:
            return "Image not found."       
        except Exception as e:
            return e

    def contrainer_exec_run(self, container, cmd: str) -> str:
        """
        Execute a command inside a Docker container.
        :param container: Docker container object
        :param cmd: Command to execute
        """ 
        # add time out

        cmd_res = container.exec_run(cmd, tty=True)  # 5 minutes timeout
        return cmd_res.output.decode("utf-8")

    def clean_build_dir(self) -> str:
        """
        Clean the /out directory in the Docker container.
        """
        def remove_call_back(container):
            container.exec_run("rm -rf /out/*", tty=True)
            container.exec_run("rm -rf /work/*", tty=True)

        # clean the /out directory
        self.run_call_back(remove_call_back)


    def run_call_back(self, call_back: str, *args, **kargs) -> str:
        """
        Explore the directory structure of a Docker image hosted on GCR.
        :param image_name: Full image name (e.g., gcr.io/oss-fuzz/libxml2)
        """
        compile_out_path = os.path.join(self.ossfuzz_dir, "build", "out", self.new_project_name)
        os.makedirs(compile_out_path, exist_ok=True)

        client = docker.from_env()
        try:
            # Create a container from the image without starting it
            container = client.containers.create(self.image_name, command="/bin/sh", tty=True,  # Allocate a pseudo-TTY
                                                 privileged=True,  # Enables privileged mode
                                                 environment={"FUZZING_LANGUAGE": self.project_lang},  # Set the environment variable
                                                 volumes={compile_out_path: {"bind": "/out", "mode": "rw"}},  # Mount the project directory
                                                 )  # Mount the cache directory (if provided
            try:
                # Start the container
                container.start()
                cmd_res = call_back(container, *args)
                if isinstance(cmd_res, str):
                    return cmd_res
                else:
                    return cmd_res.output.decode("utf-8")

            finally:
                # Clean up by removing the container
                container.remove(force=True)

        except Exception as e:
            return f"{DockerResults.Error}: {e}"
      
    def run_cmd(self, cmd_list: list[str], timeout: int = None, **kargs) -> str:

        client = docker.from_env()
        try:
            container = client.containers.run(
                self.image_name,
                command=cmd_list,  # Simulating a long-running process
                detach=True,
                tty=True, 
                privileged=True,  # Enables privileged mode
                environment={"FUZZING_LANGUAGE": self.project_lang},  # Set the environment variable
                **kargs
            )

            # Wait for the container to exit, with a timeout
            container.wait(timeout=timeout)  # Timeout in seconds

            logs = container.logs().decode('utf-8') 

            container.stop()
            container.remove()
            
            return logs

        except Exception as e:
            container.stop()
            container.remove()
            return f"{DockerResults.Error}: {e}"





    # def get_all_files(self, start_path: str) -> list[str]:
    #     '''Get all files in the project directory'''
        
    #     def find_call_back(container, cmd):
    #         return container.exec_run(cmd)

    #     cmd = "find {}".format(start_path)
    #     # Execute `find` command to recursively list files and directories
    #     results = self.run_docker_cmd(self.image_name, find_call_back, cmd)

    #     output = results.output.decode("utf-8").strip()
    #     if output is None:
    #         return []

    #     # split the directory structure
    #     all_file = output.split("\n")
    #     return all_file

    # def get_header_context(self) -> list[str]:
    #     '''Get the header information from the project harness file'''

    #     self.logger.info("Get the header information from the project harness file used without tool ")
    #     # Get the harness file path
    #     harness_path = self.oss_fuzz_tool.get_harness_and_fuzzer()[1]

    #     #  read the content of the harness file from the docker image
    #     def read_file(container, file_path):
    #         return container.exec_run("cat {}".format(file_path))

    #     results = self.run_docker_cmd(self.image_name, read_file, harness_path)
    #     output = results.output.decode("utf-8").strip()
    #     if output == "":
    #         return []

    #     # split the directory structure
    #     all_file = output.split("\n")

    #     header_list = []
    #     # Read the content of the harness file

    #     # only read the header part
    #     for line in all_file:

    #         # TODO this only works for C++ and c project
    #         if "#include" in line:
    #             header_list.append(line.strip())
    #         #
    #         if self.oss_fuzz_tool.get_entry_function() in line:
    #             break

    #     return header_list

    # def get_header_path(self, header_name: str) -> str:
       
    #     # To find the header file in the container, we need find the original harness file
    #     # and then find path of the header file
    #     def find_call_back(container, cmd):
    #         return container.exec_run(cmd)

    #     # LLM may not give the correct head file name
    #     if "/" in header_name:
    #         header_name = header_name.split("/")[-1]

    #     cmd = "find /src/ -type f -name {}".format(header_name)
    #     # Execute `find` command to recursively list files and directories
    #     results = self.run_docker_cmd(self.image_name, find_call_back, cmd)
    #     output = results.output.decode("utf-8").strip()

    #     if output == "":
    #         msg = "No {} found!".format(header_name)
    #         if self.logger:
    #             self.logger.info(msg)
    #         return msg

    #     # split the directory structure
    #     path_list = output.split("\n")

    #     if len(path_list) > 1:

    #         index = self.header_index_mapping[header_name]
    #         if index == len(path_list):
    #             index = 0
    #             self.header_index_mapping[header_name] = 0
    #         else:
    #             self.header_index_mapping[header_name] += 1
            
    #         if self.logger:
    #             msg = "Multiple header files found! {}".format(path_list)
    #             self.logger.info(msg)
           
    #         return path_list

    #     # Get the directory of path harness file
    #     harness_path = OSSFuzzUtils(self.ossfuzz_dir, self.project_name, self.new_project_name, self.logger).get_harness_and_fuzzer()[1]
    #     dir_a = os.path.dirname(harness_path)

    #     # Calculate the relative path from directory A to path B
    #     relative_path = os.path.relpath(path_list[0], start=dir_a)

    #     self.logger.info(f"Tool call for {header_name}, return:{relative_path}")

    #     return relative_path
