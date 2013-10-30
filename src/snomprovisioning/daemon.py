#!/usr/bin/python
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

import sys
import os

# daemonizing function
def become_daemon(pid_file=None):
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		raise Exception("Fork failed, can't become daemon: %d (%s)" % (e.errno, e.strerror))
		sys.exit(1)
	os.chdir("/")
   	os.setsid()
	os.umask(0)
	
	pid = os.getpid()
	if pid_file:
		try:
			f = open(pid_file, "w")
			f.write(str(pid)+"\n")
			f.close()
		except IOError:
			raise Exception('Cannot write PID in pidfile %s' % pid_file)
	return pid
