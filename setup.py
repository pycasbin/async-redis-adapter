from os import path

from setuptools import setup, find_packages

desc_file = "README.md"

with open(desc_file, "r") as fh:
    long_description = fh.read()

here = path.abspath(path.dirname(__file__))
# get the dependencies and installs
with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    all_reqs = f.read().split("\n")

install_requires = [x.strip() for x in all_reqs if "git+" not in x]

setup(
    name="casbin_async_redis_adapter",
    author="BustDot",
    author_email="Bust.dev@outlook.com",
    description="Async Redis Adapter for PyCasbin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pycasbin/async-redis-adapter",
    keywords=[
        "casbin",
        "Redis",
        "casbin-adapter",
        "async",
        "rbac",
        "access control",
        "abac",
        "acl",
        "permission",
    ],
    packages=find_packages(),
    install_requires=install_requires,
    python_requires=">=3.8",
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
