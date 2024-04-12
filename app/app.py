from bottle import install, run, TEMPLATE_PATH
from bottle.ext import sqlalchemy as orm
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.api
import app.models
from app.scripts.registration import register_users

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TEMPLATE_PATH.insert(0, 'app/views/')


def run_server():
    # database setup
    engine = create_engine('sqlite:///:memory:', echo=True)
    app.models.base.Base.metadata.create_all(engine)

    # initialize database
    Session = sessionmaker(bind=engine)
    session = Session()

    register_users(session)

    session.commit()
    session.close()


    # run server
    install(orm.Plugin(
        engine,
        keyword='db',
    ))
    run(host='0.0.0.0', port=8080)

