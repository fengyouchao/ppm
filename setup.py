from setuptools import setup, find_packages

PACKAGE = "ppm"
NAME = "ppm"
DESCRIPTION = "Private Password Manager"
AUTHOR = "Youchao Feng"
AUTHOR_EMAIL = "fengyouchao@gmail.com"
URL = "https://github.com/fengyouchao/ppm"
VERSION = __import__(PACKAGE).__version__

setup(
        name=NAME,
        version=VERSION,
        description=DESCRIPTION,
        # long_description=read("README.md"),
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        license="Apache License, Version 2.0",
        url=URL,
        packages=find_packages(),
        classifiers=[
            "Development Status :: 1 - Alpha",
            "Environment :: Web Environment",
            "Intended Audience :: Developers",
            "Operating System :: OS Independent",
            "Programming Language :: Python",
        ],
        entry_points={
            'console_scripts': [
                'ppm = ppm.ppm:main',
            ]
        },
        zip_safe=False,
)
