import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt") as f:
    required = f.read().splitlines()

setuptools.setup(
    name="anonymizer",
    version="1.0.0",
    author="Philip Buttinger, Emanuele Viglianisi, Robert Miksch, Gustavo Puma",
    description="Anonymizer for JSON objects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/runstatic/anonymizer",
    packages=setuptools.find_packages(),
    install_requires=required,
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.5",
)
