from setuptools import setup, find_packages

setup(
    name="tcpscan",
    version="0.1",
    packages=find_packages(),  # Finds 'tcpscan' package
    entry_points={
        'console_scripts': [
            'tcpscan = tcpscan.cli:main',  # maps `tcpscan` command to cli.py's main()
        ],
    },
    python_requires='>=3.6',
    author="Your Name",
    description="A simple TCP port scanner CLI tool",
)
