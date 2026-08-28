''


def get_data_files():
    ''
    import sys
    from os.path import abspath, dirname, exists, join, split

    path = abspath(dirname(__file__))
    starting_points = [path]
    if not path.startswith(sys.prefix):
        starting_points.append(sys.prefix)
    for path in starting_points:

        while path != '/':
            share_jupyterhub = join(path, 'share', 'jupyterhub')
            static = join(share_jupyterhub, 'static')
            if all(exists(join(static, f)) for f in ['components', 'css']):
                return share_jupyterhub
            path, _ = split(path)

    return ''



DATA_FILES_PATH = get_data_files()
