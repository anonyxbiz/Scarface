from setuptools import setup, find_packages

# Read the requirements from the requirements.txt file
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="Scarface",
    version="2.0.5",
    description="Scarface - Asynchronous framework built on top of Quart to implement custom security, perfomance and efficiency in deploying python apps.",
    author="Anonyxbiz",
    author_email="biz@anonyxis.life",
    url="https://github.com/anonyxbiz/scarface",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    py_modules=['Scarface'],
    python_requires='>=3.6',
)
