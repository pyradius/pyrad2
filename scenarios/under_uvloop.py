import asyncio, functools, runpy, sys
import uvloop

asyncio.run = functools.partial(asyncio.run, loop_factory=uvloop.new_event_loop)
runpy.run_path(sys.argv[1], run_name="__main__")

