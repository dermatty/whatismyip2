from importlib.metadata import version
import toml, os

try:
    cdir = os.path.dirname(os.path.realpath(__file__))
    with open(cdir + "/../pyproject.toml", mode="r") as config:
        toml_file = toml.load(config)
    __version__ = toml_file["project"]["version"]
    __appname__ = "whatismyip2" + __version__.split(".")[0]
    __appabbr__ = "wip2" + __version__.split(".")[0]
    __startmode__ = "dev"
except Exception as e:
    __startmode__ = "systemd"
    __appname__ = "whatismyip2"
    __appabbr__ = "wip2"
    __version__ = version(__appname__)
