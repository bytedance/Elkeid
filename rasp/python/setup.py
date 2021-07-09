import setuptools

setuptools.setup(
    name="rasp",
    version="1.0.0",
    description="CPython 2/3 Hook/RASP/IAST FrameWork",
    author="DuHu,HuangRuibin,LiuPan,LuoZeyu,PanXiting,",
    author_email="duhu@bytedance.com,huangruibin.moon@bytedance.com,"
                 "liupan.patte@bytedance.com,luozeyu@bytedance.com,"
                 "panxiting@bytedance.com",
    maintainer="DuHu,PanXiting",
    maintainer_email="duhu@bytedance.com,panxiting@bytedance.com",
    url="https://code.byted.org/security/iast-python",
    license="APACHE",
    packages=setuptools.find_packages(),
    package_data={"": ["resource/*"]},
    include_package_data=True,
    python_requires='>=2.7',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: No Input/Output (Daemon)",
        'Environment :: Web Environment',
        'Environment :: Console',
        "Intended Audience :: Developers",
        'Intended Audience :: System Administrators',
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: Chinese (Simplified)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Topic :: Security",

    ],
    platforms=["Linux"],
    install_requires=[],
    entry_points={
        'console_scripts': [
            'rasp_static_attach = rasp:rasp_static_attach',
            'rasp_static_detach = rasp:rasp_static_detach',
            'rasp_dyn_attach = rasp:rasp_dynamic_attach',
            'rasp_dyn_detach = rasp:rasp_dynamic_detach',
        ]
    },
    zip_safe=False
)
