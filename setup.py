from setuptools import setup

setup(
    name="security_scanner",
    version="0.1.0",
    description="A passive security reconnaissance tool",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/security_scanner",
    py_modules=["security_scanner"],
    install_requires=[
        "requests",
        "dnspython",
        "python-whois",
        "beautifulsoup4",
    ],
    entry_points={
        "console_scripts": [
            "security-scanner = security_scanner:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)