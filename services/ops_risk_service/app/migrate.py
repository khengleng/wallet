from .db import Base, engine
from . import models  # noqa: F401


def main():
    Base.metadata.create_all(bind=engine)
    print("ops-risk schema ensured")


if __name__ == "__main__":
    main()
