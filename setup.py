from setuptools import setup, find_packages
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
setup(
    name="jarVisXstar",
    version="2.2.0",
    author="bintang657",
    author_email="dwatu8720@gmail.com",
    description="Perpustakaan keamanan web paling canggih - WAF, JWT, Rate Limiter, Honeypot, dan banyak lagi.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bintang657/jarVisXstar",
    project_urls={
        "Bug Tracker": "https://github.com/bintang657/jarVisXstar/issues",
        "Source Code": "https://github.com/bintang657/jarVisXstar",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
    ],
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "PyJWT>=2.8.0",
        "redis>=5.0.0",
        "bleach>=6.0.0",
        "cryptography>=41.0.0",
        "bcrypt>=4.0.0",
        "Flask>=2.3.0",
        "Django>=4.2",
        "fastapi>=0.100.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "jvx-scan=jarVisXstar.cli.scanner:main",
        ],
    },
    include_package_data=True,
)