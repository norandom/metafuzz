#!C:\python25\python.exe
#
# (c) 2009, the grugq <the.grugq@gmail.com>

from sqlalchemy import (Column, Integer, String, ForeignKey, create_engine)
from sqlalchemy.orm import (relation, backref, sessionmaker)
from sqlalchemy.ext.declarative import (declarative_base,)

from contextlib import contextmanager


Base = declarative_base()

class Module(Base):
    __tablename__ = "modules"

    id  = Column(Integer, primary_key=True)
    name= Column(String, nullable=False)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<Module(%d) %s>" % (self.id, self.name)

class Function(Base):
    __tablename__ = "functions"

    id  = Column(Integer, primary_key=True)
    name= Column(String, nullable=False)
    address     = Column(Integer, nullable=False)
    module_id   = Column(Integer, ForeignKey("modules.id"))

    module  = relation(Module, backref=backref("functions", order_by=address))

    def __init__(self, address, name, module):
        self.address= address
        self.name   = name
        self.module = module

    def __repr__(self):
        return "<Function 0x%08x %s [%s]>" % (self.address, self.name, self.module.name)

class Frame(Base):
    __tablename__ = "frames"

    id  = Column(Integer, primary_key=True)
    sequence    = Column(Integer, nullable=False)
    function_id = Column(Integer, ForeignKey("functions.id"))
    trace_id    = Column(Integer, ForeignKey("stacktraces.id"))

    function    = relation(Function)

    def __init__(self, sequence, function, trace):
        self.sequence = sequence
        self.function = function
        self.stacktrace = trace

class StackTrace(Base):
    __tablename__ = "stacktraces"

    id  = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)

    frames  = relation(Frame, order_by=Frame.sequence, backref="stacktrace")

    def __init__(self, filename):
        self.filename = filename

    def __repr__(self):
        return "<StackTrace: %s [frames: %d]>" % (self.filename,)


class TraceDB(object):
    def __init__(self, uri):
        self.engine = create_engine(uri)
        self.create_session = sessionmaker(bind=self.engine)

        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self):
        session = self.create_session()
        try:
            yield session
        except:
            session.rollback()
            raise
        else:
            session.commit()
