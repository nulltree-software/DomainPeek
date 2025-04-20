import setuptools
import os

# Function to read the contents of requirements.txt
def get_requirements(file_path='requirements.txt'):
    with open(file_path, 'r') as f:
        # return requirements removing comments and empty lines
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Function to read the README file for the long description
def get_long_description(file_path='README.md'):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    # Fallback description if README.md doesn't exist
    return 'A tool to query DNS, WHOIS, and Email Authentication information for domains using native Python libraries.' # Updated fallback

# Package Metadata
setuptools.setup(
    # How the package will be named (e.g., pip install domain-peek-tool)
    # Use hyphens here. Cannot be the same as the module name 'domainpeek'.
    name="domain-peek-tool",
    version="1.1",
    author="Thegen Jackson",
    description="Get DNS, WHOIS, and basic Email Authentication (SPF, DMARC, common DKIM Selectors) info using python-whois and dnspython.",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/nulltree-software/domainpeek",
    license="MIT",

    # Package Configuration
    # Tells setuptools your code is in a single file named domainpeek.py
    py_modules=["domainpeek"],

    # Dependencies needed for the script to run
    install_requires=get_requirements(),

    # Command-Line Script Definition
    # This creates the 'domainpeek' command that points to the main function
    entry_points={
        'console_scripts': [
            # command_name = module_name:function_name
            'domainpeek = domainpeek:main',
        ],
    },

    # Optional Classifiers (for PyPI)
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
        "Topic :: Internet :: Name Service (DNS)",
    ],
    python_requires='>=3.7', # Minimum Python version based on f-strings, type hints etc
)