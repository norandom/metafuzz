#!C:\python25\python.exe
#
# (c) 2009, the grugq <the.grugq@gmail.com>


from sqlalchemy import (Column, Integer, String)


class Module(Base):
    __tablename__ = "modules"

    id  = Column(Integer, primary=True)
    name= Column(String, nullable=False)

class Function(Base):
    __tablename__ = "functions"

    id  = Column(Integer, primary=True)
    name= Column(String, nullable=False)
    module_id   = Column(Integer, ForeignKey("modules.id"))

class StackTrace(Base):
    __tablename__ = "stacktraces"

    id  = Column(Integer, primary=True)
    filename = Column(String, nullable=False)


class Frame(Base):
    __tablename__ = "frames"

    id  = Column(Integer, primary=True)
    sequence    = Column(Integer, nullable=False)
    function_id = Column(Integer, ForeignKey("functions.id"))
    trace_id    = Column(Integer, ForeignKey("stacktraces.id"))

def create_stack_trace(fname, frames):
    trace = StackTrace(fname)

    for sequence, func_id in enumerate(frames):
        trace.append(Frame(func_id, sequence=sequence))
