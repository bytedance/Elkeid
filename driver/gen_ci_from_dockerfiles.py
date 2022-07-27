import yaml
import os
from collections import OrderedDict


all_dockers = os.listdir("driver/dockerfiles")

black_list = []

all_vms = []

jobs = []


def gen_job(vmname):
    some_data = OrderedDict(
        {
            "runs-on": "ubuntu-latest",
            "steps": [
                OrderedDict({
                    "uses": "actions/checkout@v2",
                    "with": {
                        "submodules": "recursive"
                    }
                }),
                OrderedDict({
                    "name": "Login to Docker Hub",
                    "uses": "docker/login-action@v1",
                    "with": {
                        "username": "${{secrets.DOCKERHUB_USERNAME}}",
                        "password": "${{secrets.DOCKERHUB_TOKEN}}"
                    }
                }),
                OrderedDict({
                    "name": "Set up Docker Buildx "+vmname,
                    "uses": "docker/setup-buildx-action@v1"
                }),

                OrderedDict({
                    "name": "Build "+vmname,
                    "uses": "docker/build-push-action@v2",
                    "with": {
                        "file": "driver/dockerfiles/Dockerfile."+vmname,
                        "push": True,
                        "tags": "elkeidteam/elkeid_driver_"+vmname+":latest"
                    }
                }),

                OrderedDict({
                    "name": "Docker Hub Description "+vmname,
                    "uses": "peter-evans/dockerhub-description@v3",
                    "with": {
                        "username": "${{secrets.DOCKERHUB_USERNAME}}",
                        "password": "${{secrets.DOCKERHUB_TOKEN}}",
                        "repository": "elkeidteam/elkeid_driver_"+vmname,
                        "short-description": "${{github.event.repository.description}}",
                    }
                }),

                OrderedDict({
                    "name": "Extract "+vmname,
                    "id": "extract-"+vmname,
                    "uses": "shrink/actions-docker-extract@v1",
                    "with": {
                        "image": "elkeidteam/elkeid_driver_"+vmname+":latest",
                        "path": "/ko_output/."
                    }
                }),
                OrderedDict({
                    "name": "Upload "+vmname,
                    "uses": "actions/upload-artifact@v3",
                    "with": {
                        "path": "${{steps.extract-"+vmname+".outputs.destination}}",
                        "name": "elkeid_driver_"+vmname
                    }
                })
            ]

        }
    )
    return some_data


for each_dockers in all_dockers:
    all_vms.append(each_dockers.replace("Dockerfile.", ""))

yaml_cfg_build = OrderedDict(
    {
        "name": "Elkeid_driver",
        "on": {
            "push": {
                "branches": [
                    "main",
                ]
            },
            "schedule": ["cron : '0 3 1 * *'"]
        }
    }
)

yaml_cfg_release = OrderedDict(
    {
        "name": "Elkeid_driver",
        "on": {
            "push": {
                "tags": [
                    "'v*'"
                ]
            },
        }
    }
)

create_release_job = OrderedDict(
    {
        "runs-on": "ubuntu-latest",
        "permissions": "write-all",
        "steps": [
            OrderedDict({
                "name": "Create Release",
                "id": "create_release",
                "uses": "actions/create-release@v1",
                "env": {
                        "GITHUB_TOKEN": "${{secrets.GITHUB_TOKEN}}"
                },
                "with": {
                    "tag_name": "${{github.ref}}",
                    "release_name": "Release ${{github.ref}}",
                    "draft": False,
                    "prerelease": False,
                }
            }),
            OrderedDict({
                "uses": "actions/download-artifact@v3",
                "with": {
                    "path": "~/all_elkeid_drivers"
                }
            }),
            OrderedDict({
                "name": "Pack artifact ",
                "run": "zip -r elkeid_driver.zip ~/all_elkeid_drivers"
            }),

            OrderedDict({
                "name": "Upload Release Asset ",
                "id": "upload-release-asset",
                "uses": "actions/upload-release-asset@v1",
                "env": {
                        "GITHUB_TOKEN": "${{secrets.GITHUB_TOKEN}}"
                },
                "with": {
                    "upload_url": "${{steps.create_release.outputs.upload_url}}",
                    "asset_path": "./elkeid_driver.zip",
                    "asset_name": "elkeid_driver.zip",
                    "asset_content_type": "application/zip"
                },
            })
        ]
    }
)

total_jobs_list = []
for each in all_vms:
    if each not in black_list:
        total_jobs_list.append("build_"+each)
create_release_job.update({"needs": total_jobs_list})

total_jobs_build = OrderedDict({})
total_jobs_release = OrderedDict({})


all_vms.sort()

for each in all_vms:
    if each not in black_list:
        tmp_job = gen_job(each)
        total_jobs_build.update({"build_"+each: tmp_job})
        total_jobs_release.update({"build_"+each: tmp_job})

total_jobs_release.update({"release_all": create_release_job})


yaml_cfg_build.update({"jobs": total_jobs_build})
yaml_cfg_release.update({"jobs": total_jobs_release})


def represent_dictionary_order(self, dict_data):
    return self.represent_mapping('tag:yaml.org,2002:map', dict_data.items())


def setup_yaml():
    yaml.add_representer(OrderedDict, represent_dictionary_order)


setup_yaml()


with open(".github/workflows/Elkeid_driver_build.yml", "w") as f:
    config_data = yaml.dump(yaml_cfg_build, default_flow_style=False)
    config_data = config_data.replace("'", "")
    f.write(config_data)

with open(".github/workflows/Elkeid_driver_release.yml", "w") as f:
    config_data = yaml.dump(yaml_cfg_release, default_flow_style=False)
    config_data = config_data.replace("'", "")
    f.write(config_data)
